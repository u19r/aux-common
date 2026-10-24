use std::{future::Future, sync::Arc, time::Duration};

use alloc_counter::AllocationReport;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(not(target_arch = "wasm32"))]
use http_request::HttpClientBuilder;
use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    errors::ErrorKind,
    jwk::{KeyAlgorithm, PublicKeyUse},
};
use serde_json::json;

use crate::{
    AllowedAlgorithms, ClaimErrorKind, JwksCachePolicy, JwksSource, JwksUrl, JwtDecodeErrorKind,
    JwtVerifier, RemoteJwksSource, SignatureAlgorithm, TokenKind, VerificationPolicy,
    jwks::{
        Claims, CountingTransport, FixedClock, HMAC_SECRET, build_hmac_verifier,
        build_remote_verifier, build_verifier, hmac_token, id_header, jwk, policy,
        registered_claims, signed_raw_token, signed_token, signed_value_token, token,
        token_without_iat, valid_claims,
    },
};

fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn given_valid_static_jwks_when_verifying_static_token_then_returns_typed_claims() {
    // Given a valid signed access token and a verifier with a static JWKS
    // document.
    let verifier = build_verifier();
    let token = token(valid_claims());

    // When the synchronous typed verification path is used.
    let verified = verifier.verify_static::<Claims>(&token, &policy());

    // Then the registered metadata and typed application claims are retained.
    let verified = verified.expect("valid static token");
    assert_eq!(verified.algorithm, SignatureAlgorithm::RS256);
    assert_eq!(verified.key_id, "test-key");
    assert_eq!(verified.claims.client_id, "client-123");
}

#[test]
fn given_valid_static_token_when_verifying_static_json_claims_then_returns_payload() {
    // Given a valid token backed by the verifier's static key document.
    let verifier = build_verifier();
    let token = token(valid_claims());

    // When the convenience wrapper for static JSON claims is used.
    let verified = verifier
        .verify_static_json_claims(&token, &policy())
        .expect("valid static token");

    // Then the wrapper returns both key metadata and the original JSON claim.
    assert_eq!(verified.key_id, "test-key");
    assert_eq!(verified.claims["client_id"], "client-123");
}

#[test]
fn given_valid_claims_when_static_deserialization_type_is_incompatible_then_returns_claim_error() {
    // Given claims that satisfy the verification policy but are an object, not
    // a JSON string.
    let verifier = build_verifier();
    let token = token(valid_claims());

    // When callers request a type that cannot deserialize the verified object.
    let error = verifier
        .verify_static::<String>(&token, &policy())
        .expect_err("object claims must not deserialize as a string");

    // Then the verifier exposes its stable claim-deserialization error
    // boundary.
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Deserialize)
    );
}

#[tokio::test]
async fn given_valid_claims_when_async_deserialization_type_is_incompatible_then_returns_claim_error()
 {
    // Given claims that pass issuer, time, audience, and token-type validation.
    let verifier = build_verifier();
    let token = token(valid_claims());

    // When the asynchronous verifier is asked for an incompatible application
    // type.
    let error = verifier
        .verify::<String>(&token, &policy())
        .await
        .expect_err("object claims must not deserialize as a string");

    // Then the async path uses the same stable claim-deserialization boundary.
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Deserialize)
    );
}

#[tokio::test]
async fn given_access_policy_when_header_type_is_not_allowed_then_rejects_before_key_lookup() {
    // Given an access policy and a signed token whose typ is generic JWT, with
    // no kid so a reordered implementation would report missing-key-id instead.
    let verifier = build_verifier();
    let mut header = id_header();
    header.kid = None;
    let token = signed_token(header, valid_claims());

    // When the header is checked against the access-token typ allowlist.
    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .expect_err("generic JWT typ must not satisfy an access-token policy");

    // Then the header rule wins before key lookup (rather than exposing
    // MissingKeyId).
    assert_eq!(error.kind(), &JwtDecodeErrorKind::TokenTypeMismatch);
}

#[tokio::test]
async fn given_id_policy_when_header_is_access_token_type_then_rejects_token() {
    // Given an ID-token policy and the access-token at+jwt header.
    let verifier = build_verifier();
    let policy = VerificationPolicy::id_token()
        .issuer("https://issuer.example")
        .expect("issuer")
        .audience("aux-api")
        .expect("audience")
        .build()
        .expect("ID-token policy");

    // When the verifier applies the closed token-kind/header-type rule.
    let error = verifier
        .verify::<Claims>(&token(valid_claims()), &policy)
        .await
        .expect_err("at+jwt must not be accepted as an ID token");

    // Then the access-token representation cannot cross the ID-token boundary.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::TokenTypeMismatch);
}

#[test]
fn given_local_hmac_source_when_verifying_static_claims_then_accepts_valid_signature() {
    // Given an explicitly configured local HMAC source and symmetric allowlist.
    let verifier = build_hmac_verifier();
    let token = hmac_token(valid_claims());

    // When the static claims-only path resolves the local symmetric key.
    let claims = verifier
        .verify_static_json_claims_only(&token, &policy())
        .expect("valid local HMAC token");

    // Then the signature is verified without consulting a JWKS document.
    assert_eq!(claims["client_id"], "client-123");
}

#[test]
fn given_asymmetric_static_verifier_when_verifying_hs256_token_then_rejects_algorithm() {
    // Given a static RSA verifier and a token signed with the disallowed HS256
    // family.
    let verifier = build_verifier();
    let token = hmac_token(valid_claims());

    // When the public static claims-only verification path checks the algorithm
    // allowlist.
    let error = verifier
        .verify_static_json_claims_only(&token, &policy())
        .expect_err("HS256 must not cross an asymmetric verifier boundary");

    // Then the token is rejected before static key selection or signature
    // verification.
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::UnsupportedAlgorithm(SignatureAlgorithm::HS256)
    );
}

#[test]
fn given_none_algorithm_token_when_verifying_then_rejects_unsigned_token() {
    // Given unsigned tokens with `none` and case-variant algorithms.
    let verifier = build_verifier();
    let claims = serde_json::to_vec(&valid_claims()).expect("claims serialize");
    let unsigned = |header: &[u8]| {
        let encoded_header = URL_SAFE_NO_PAD.encode(header);
        let encoded_claims = URL_SAFE_NO_PAD.encode(&claims);
        format!("{encoded_header}.{encoded_claims}.")
    };
    let tokens = [
        unsigned(br#"{"alg":"none","typ":"at+jwt","kid":"test-key"}"#),
        unsigned(br#"{"alg":"nOnE","typ":"at+jwt","kid":"test-key"}"#),
    ];

    // When the static claims-only verification path evaluates unsigned tokens.
    for token in tokens {
        let error = verifier
            .verify_static_json_claims_only(&token, &policy())
            .expect_err("unsigned tokens must never verify");

        // Then empty signatures fail closed as malformed before any trust
        // decision.
        assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
    }
}

#[tokio::test]
async fn given_invalid_signature_when_verifying_json_claims_only_then_rejects_signature() {
    // Given a valid compact token whose signature bytes are tampered after
    // signing.
    let verifier = build_verifier();
    let token = tamper_signature(token(valid_claims()));

    // When the signature-only JSON claims path verifies the compact token.
    let error = verifier
        .verify_json_claims_only(&token, &policy())
        .await
        .expect_err("tampered signatures must fail verification");

    // Then a cryptographically invalid signature is distinguished from
    // malformed claims.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::SignatureInvalid);
}

#[test]
fn given_backend_error_kinds_when_mapping_then_preserves_security_categories() {
    // Given representative backend errors from token parsing, crypto, and key
    // validation.
    let cases = [
        (
            ErrorKind::InvalidToken.into(),
            JwtDecodeErrorKind::MalformedToken,
        ),
        (
            ErrorKind::InvalidEddsaKey.into(),
            JwtDecodeErrorKind::InvalidKey,
        ),
        (
            ErrorKind::InvalidRsaKey("bad RSA key".to_owned()).into(),
            JwtDecodeErrorKind::InvalidKey,
        ),
        (
            ErrorKind::InvalidSignature.into(),
            JwtDecodeErrorKind::SignatureInvalid,
        ),
        (
            ErrorKind::Provider("provider failed".to_owned()).into(),
            JwtDecodeErrorKind::SignatureInvalid,
        ),
        (
            ErrorKind::InvalidAlgorithm.into(),
            JwtDecodeErrorKind::UnsupportedHeader,
        ),
        (
            ErrorKind::InvalidKeyFormat.into(),
            JwtDecodeErrorKind::InvalidKey,
        ),
        (
            ErrorKind::InvalidEcdsaKey.into(),
            JwtDecodeErrorKind::InvalidKey,
        ),
        (
            ErrorKind::InvalidAlgorithmName.into(),
            JwtDecodeErrorKind::InvalidKey,
        ),
        (
            ErrorKind::ExpiredSignature.into(),
            JwtDecodeErrorKind::Expired,
        ),
    ];

    // When each backend error is mapped at the verifier's protocol boundary.
    for (backend_error, expected) in cases {
        let mapped = JwtVerifier::test_map_backend_error(backend_error);

        // Then no backend detail can silently cross the public error taxonomy.
        assert_eq!(mapped.kind(), &expected);
    }
}

#[test]
fn given_verifier_builder_without_jwks_source_when_building_then_rejects_configuration() {
    // Given a builder with no key source configured.
    let builder = JwtVerifier::builder();

    // When construction is attempted.
    let error = builder
        .build()
        .err()
        .expect("missing JWKS source must fail");

    // Then the verifier cannot exist without an explicit trust source.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksParse);
}

fn tamper_signature(token: String) -> String {
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    let replacement = if parts[2].starts_with('a') { 'b' } else { 'a' };
    parts[2].replace_range(0..1, &replacement.to_string());
    parts.join(".")
}

#[tokio::test]
async fn given_missing_exp_when_verifying_then_rejects_claims() {
    let mut claims = value_claims();
    claims.as_object_mut().unwrap().remove("exp");

    let error = build_verifier()
        .verify::<Claims>(&signed_value_token(access_header(), claims), &policy())
        .await
        .unwrap_err();

    assert!(matches!(error.kind(), JwtDecodeErrorKind::ClaimsInvalid(_)));
}

#[tokio::test]
async fn given_missing_audience_when_verifying_then_rejects_claims() {
    let mut claims = value_claims();
    claims.as_object_mut().unwrap().remove("aud");

    let error = build_verifier()
        .verify::<Claims>(&signed_value_token(access_header(), claims), &policy())
        .await
        .unwrap_err();

    assert!(matches!(error.kind(), JwtDecodeErrorKind::ClaimsInvalid(_)));
}

#[tokio::test]
async fn given_future_nbf_when_verifying_then_rejects_not_yet_valid() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.registered.nbf = Some(1_700_000_900);

    let error = verifier
        .verify::<Claims>(&token(claims), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::NotYetValid);
}

#[tokio::test]
async fn given_future_iat_when_verifying_then_rejects_issued_at() {
    let verifier = build_verifier();
    let token = token(Claims {
        registered: registered_claims(1_700_000_900, 1_700_000_900),
        token_type: crate::TokenKind::Access,
        client_id: "client-123".to_owned(),
    });

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::IssuedAtInvalid);
}

#[tokio::test]
async fn given_old_iat_when_max_age_applies_then_rejects_issued_at() {
    let verifier = build_verifier();
    let token = token(Claims {
        registered: registered_claims(1_700_000_300, 1_699_998_000),
        token_type: crate::TokenKind::Access,
        client_id: "client-123".to_owned(),
    });

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::IssuedAtInvalid);
}

fn value_claims() -> serde_json::Value {
    json!({
        "iss": "https://issuer.example",
        "sub": "subject",
        "aud": "aux-api",
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64,
        "token_type": "access",
        "client_id": "client-123"
    })
}

fn access_header() -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    header
}

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

#[tokio::test]
async fn given_valid_static_jwks_when_verifying_access_token_then_returns_typed_claims() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(Claims {
        registered: registered_claims(1_700_000_300, 1_699_999_990),
        token_type: TokenKind::Access,
        client_id: "client-123".to_owned(),
    });

    let verified = verifier.verify::<Claims>(&token, &policy).await.unwrap();

    assert_eq!(verified.algorithm, SignatureAlgorithm::RS256);
    assert_eq!(verified.key_id, "test-key");
    assert_eq!(verified.claims.client_id, "client-123");
}

#[tokio::test]
async fn given_claims_only_verification_when_token_is_valid_then_returns_json_claims() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(valid_claims());

    let claims = verifier
        .verify_json_claims_only(&token, &policy)
        .await
        .unwrap();

    assert_eq!(claims["client_id"], "client-123");
}

#[test]
fn given_static_claims_only_verification_when_token_is_valid_then_returns_json_claims() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(valid_claims());

    let claims = verifier
        .verify_static_json_claims_only(&token, &policy)
        .unwrap();

    assert_eq!(claims["client_id"], "client-123");
}

#[tokio::test]
async fn given_claims_only_verification_when_payload_has_duplicate_member_then_rejects_token() {
    let token = signed_raw_token(
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"}"#,
        br#"{"iss":"https://issuer.example","iss":"https://issuer.example","aud":"aux-api","exp":1700000300,"iat":1699999990,"token_type":"access","client_id":"client-123"}"#,
    );

    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_trailing_json_in_header_when_verifying_then_rejects_token() {
    let token = signed_raw_token(
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"} {}"#,
        serde_json::to_string(&valid_claims()).unwrap().as_bytes(),
    );

    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_trailing_json_in_payload_when_verifying_then_rejects_token() {
    let payload = format!("{} {{}}", serde_json::to_string(&valid_claims()).unwrap());
    let token = signed_raw_token(
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"}"#,
        payload.as_bytes(),
    );

    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_escaped_duplicate_member_when_verifying_then_rejects_token() {
    // Given a payload where the duplicate hides behind a JSON escape, so a
    // raw-text comparison would miss it while a decoded-name comparison
    // must still catch it.
    let mut payload = serde_json::to_string(&valid_claims()).expect("claims serialize");
    payload.pop();
    payload.push_str(",\"\\u0063lient_id\":\"mallory\"}");

    let token = signed_raw_token(
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"}"#,
        payload.as_bytes(),
    );

    // When the claims-only verification path inspects the payload.
    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    // Then the escaped duplicate fails closed like a plain duplicate.
    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_nested_escaped_duplicate_member_when_verifying_then_rejects_token() {
    // Given a duplicate hidden inside a nested object with one spelling
    // escaped, exercising the recursive duplicate-rejecting visitor.
    let mut payload = serde_json::to_string(&valid_claims()).expect("claims serialize");
    payload.pop();
    payload.push_str(",\"nested\":{\"a\":1,\"\\u0061\":2}}");

    let token = signed_raw_token(
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"}"#,
        payload.as_bytes(),
    );

    // When the claims-only verification path inspects the payload.
    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    // Then the nested duplicate fails closed.
    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_hmac_signature_under_rs256_header_when_verifying_then_rejects_token() {
    // Given token bytes signed with the HMAC secret while the header claims
    // asymmetric RS256, the classic key-confusion shape.
    let message = format!(
        "{}.{}",
        base64_url_encode(br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt"}"#),
        base64_url_encode(
            serde_json::to_string(&valid_claims())
                .expect("claims serialize")
                .as_bytes()
        ),
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &EncodingKey::from_secret(HMAC_SECRET),
        Algorithm::HS256,
    )
    .expect("hmac sign");
    let token = format!("{message}.{signature}");

    // When the asymmetric verifier evaluates the confused token.
    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    // Then the token is rejected and never verifies as its claimed algorithm.
    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::SignatureInvalid | JwtDecodeErrorKind::InvalidKey
    ));
}

#[tokio::test]
async fn given_none_algorithm_with_signature_bytes_when_verifying_then_rejects_token() {
    // Given an unsigned algorithm label paired with trailing signature bytes,
    // so the compact shape alone cannot exonerate the token.
    let token = format!(
        "{}.{}.{}",
        base64_url_encode(br#"{"alg":"none","kid":"test-key","typ":"at+jwt"}"#),
        base64_url_encode(
            serde_json::to_string(&valid_claims())
                .expect("claims serialize")
                .as_bytes()
        ),
        base64_url_encode(b"not-a-signature"),
    );

    // When the verifier evaluates the token.
    let error = build_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .unwrap_err();

    // Then the token fails closed regardless of the trailing bytes. The
    // undecodable `none` algorithm resolves against the closed set before
    // the backend parses the header, so the rejection carries the header
    // category instead of a claims-deserialization error.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::UnsupportedHeader);
}

#[tokio::test]
async fn given_unknown_missing_or_mistyped_alg_when_verifying_then_rejects_header() {
    // Given headers whose `alg` is unknown, missing, or mistyped, each
    // paired with otherwise valid claims. (Non-JSON headers never reach the
    // algorithm check: duplicate-shape validation rejects them first with
    // `DuplicateJsonMember`, a pre-existing pinned convention.)
    let payload = base64_url_encode(
        serde_json::to_string(&valid_claims())
            .expect("claims serialize")
            .as_bytes(),
    );
    let headers = [
        base64_url_encode(br#"{"alg":"HS999","kid":"test-key","typ":"at+jwt"}"#),
        base64_url_encode(br#"{"kid":"test-key","typ":"at+jwt"}"#),
        base64_url_encode(br#"{"alg":256,"kid":"test-key","typ":"at+jwt"}"#),
    ];

    // When each token reaches the verifier.
    for header in headers {
        let token = format!("{header}.{payload}.c2ln");
        let error = build_verifier()
            .verify_json_claims_only(&token, &policy())
            .await
            .unwrap_err();

        // Then every undecodable algorithm fails with a header-category
        // error before key lookup or signature verification.
        assert_eq!(error.kind(), &JwtDecodeErrorKind::UnsupportedHeader);
    }
}

#[test]
fn given_invalid_base64_header_when_verifying_then_rejects_malformed_token() {
    // Given a compact token whose header segment is not base64url at all.
    let payload = base64_url_encode(
        serde_json::to_string(&valid_claims())
            .expect("claims serialize")
            .as_bytes(),
    );
    let token = format!("!!!.{payload}.c2ln");

    // When the static claims-only path evaluates the token.
    let error = build_verifier()
        .verify_static_json_claims_only(&token, &policy())
        .expect_err("undecodable header must fail");

    // Then the shape failure precedes any algorithm decision.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
}

#[tokio::test]
async fn given_generic_jwt_policy_when_token_has_no_product_type_then_accepts() {
    let verifier = build_verifier();
    let policy = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .build()
        .unwrap();
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "subject",
        "aud": "aux-api",
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64
    });

    let verified = verifier
        .verify_json_claims(&signed_value_token(id_header(), claims), &policy)
        .await
        .unwrap();

    assert_eq!(verified.algorithm, SignatureAlgorithm::RS256);
}

#[tokio::test]
async fn given_generic_jwt_policy_without_audience_when_token_has_no_audience_then_accepts() {
    let verifier = build_verifier();
    let policy = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .without_audience()
        .build()
        .unwrap();
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "subject",
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64
    });

    let verified = verifier
        .verify_json_claims(&signed_value_token(id_header(), claims), &policy)
        .await
        .unwrap();

    assert_eq!(verified.claims["sub"], "subject");
}

#[tokio::test]
async fn given_policy_allowing_missing_iat_when_token_has_no_iat_then_accepts() {
    let verifier = build_verifier();
    let policy = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .allow_missing_issued_at()
        .build()
        .unwrap();

    let verified = verifier
        .verify_json_claims(&token_without_iat(), &policy)
        .await
        .unwrap();

    assert_eq!(verified.claims["aud"], "aux-api");
}

#[tokio::test]
async fn given_expired_token_when_verifying_then_rejects_expiration() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(Claims {
        registered: registered_claims(1_699_999_900, 1_699_999_800),
        token_type: TokenKind::Access,
        client_id: "client-123".to_owned(),
    });

    let error = verifier
        .verify::<Claims>(&token, &policy)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::Expired);
}

#[tokio::test]
async fn given_token_expiring_at_current_second_when_verifying_then_rejects_expiration() {
    let verifier = build_verifier();
    let token = token(Claims {
        registered: registered_claims(1_700_000_000, 1_699_999_990),
        token_type: TokenKind::Access,
        client_id: "client-123".to_owned(),
    });

    let boundary_policy = VerificationPolicy::access_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .leeway(Duration::ZERO)
        .build()
        .unwrap();
    let error = verifier
        .verify::<Claims>(&token, &boundary_policy)
        .await
        .expect_err("the expiration boundary must be exclusive");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::Expired);
}

#[tokio::test]
async fn given_wrong_audience_when_verifying_then_rejects_audience() {
    let verifier = build_verifier();
    let mut claims = Claims {
        registered: registered_claims(1_700_000_300, 1_699_999_990),
        token_type: TokenKind::Access,
        client_id: "client-123".to_owned(),
    };
    claims.registered.aud = Some(crate::Audience::Single("other-api".to_owned()));
    let token = token(claims);

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
}

#[tokio::test]
async fn given_missing_iat_when_verifying_then_rejects_claims() {
    let verifier = build_verifier();
    let token = token_without_iat();

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::IssuedAtInvalid);
}

#[tokio::test]
async fn given_wrong_issuer_when_verifying_then_rejects_issuer() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.registered.iss = "https://other-issuer.example".to_owned();

    let error = verifier
        .verify::<Claims>(&token(claims), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::IssuerMismatch);
}

#[tokio::test]
async fn given_wrong_token_type_when_verifying_then_rejects_token_type() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.token_type = TokenKind::Refresh;

    let error = verifier
        .verify::<Claims>(&token(claims), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::TokenTypeMismatch);
}

#[tokio::test]
async fn given_wrong_client_when_verifying_then_rejects_client() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.client_id = "other-client".to_owned();

    let error = verifier
        .verify::<Claims>(&token(claims), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::ClientMismatch);
}

#[tokio::test]
async fn given_missing_kid_when_verifying_then_rejects_key_selection() {
    let verifier = build_verifier();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());
    let token = signed_token(header, valid_claims());

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::MissingKeyId);
}

#[tokio::test]
async fn given_unknown_kid_when_verifying_then_rejects_key_selection() {
    let verifier = build_verifier();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some("unknown-key".to_owned());
    let token = signed_token(header, valid_claims());

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::KeyNotFound);
}

#[tokio::test]
async fn given_duplicate_kid_in_jwks_when_verifying_then_rejects_ambiguous_key() {
    let mut jwk = jwk();
    jwk.common.key_id = Some("test-key".to_owned());
    let jwks = serde_json::json!({ "keys": [jwk.clone(), jwk] }).to_string();
    let verifier = JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks).unwrap())
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();

    let error = verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::AmbiguousKeyId);
}

#[tokio::test]
async fn given_unsupported_header_key_url_when_verifying_then_rejects_header() {
    let verifier = build_verifier();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    header.jku = Some("https://attacker.example/jwks.json".to_owned());
    let token = signed_token(header, valid_claims());

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::UnsupportedHeader);
}

#[tokio::test]
async fn given_certificate_or_critical_header_when_verifying_then_rejects_header() {
    // Given validly signed tokens that smuggle certificate material or
    // critical extensions through the header, including a degenerate empty
    // `crit` list that names no extension but still uses the header.
    let headers = [
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt","x5u":"https://attacker.invalid/cert.pem"}"#.as_slice(),
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt","x5c":["QUJD"]}"#.as_slice(),
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt","crit":["exp"]}"#.as_slice(),
        br#"{"alg":"RS256","kid":"test-key","typ":"at+jwt","crit":[]}"#.as_slice(),
    ];
    let claims = serde_json::to_string(&valid_claims()).expect("claims serialize");

    // When each token reaches the verifier with an otherwise valid signature.
    for header in headers {
        let token = signed_raw_token(header, claims.as_bytes());
        let error = build_verifier()
            .verify_json_claims_only(&token, &policy())
            .await
            .unwrap_err();

        // Then header-supplied key material and critical extensions fail
        // closed before any trust decision.
        assert_eq!(error.kind(), &JwtDecodeErrorKind::UnsupportedHeader);
    }
}

#[tokio::test]
async fn given_duplicate_header_member_when_verifying_then_rejects_token() {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","alg":"RS256","kid":"test-key"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example"}"#);
    let token = format!("{header}.{payload}.signature");

    let error = build_verifier()
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert!(matches!(
        error.kind(),
        JwtDecodeErrorKind::ClaimsInvalid(crate::ClaimErrorKind::DuplicateJsonMember)
    ));
}

#[tokio::test]
async fn given_access_token_with_application_typ_when_policy_allows_then_accepts() {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("application/at+jwt".to_owned());
    let policy = VerificationPolicy::access_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .allow_application_access_token_typ()
        .build()
        .unwrap();

    build_verifier()
        .verify::<Claims>(&signed_token(header, valid_claims()), &policy)
        .await
        .unwrap();
}

#[tokio::test]
async fn given_id_token_with_multiple_audiences_when_azp_matches_then_accepts() {
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "subject",
        "aud": ["aux-api", "other-api"],
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64,
        "token_type": "id",
        "azp": "client-123",
        "nonce": "nonce-123"
    });
    let policy = VerificationPolicy::id_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .nonce("nonce-123")
        .unwrap()
        .build()
        .unwrap();

    build_verifier()
        .verify_json_claims(&signed_value_token(id_header(), claims), &policy)
        .await
        .unwrap();
}

#[tokio::test]
async fn given_id_token_with_wrong_nonce_when_verifying_then_rejects_nonce() {
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "aud": "aux-api",
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64,
        "token_type": "id",
        "client_id": "client-123",
        "nonce": "wrong"
    });
    let policy = VerificationPolicy::id_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .nonce("nonce-123")
        .unwrap()
        .build()
        .unwrap();

    let error = build_verifier()
        .verify_json_claims(&signed_value_token(id_header(), claims), &policy)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::NonceMismatch);
}

#[tokio::test]
async fn given_refresh_token_policy_when_signed_claims_match_then_accepts_without_revocation_logic()
{
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "aud": "aux-api",
        "exp": 1_700_000_300_i64,
        "iat": 1_699_999_990_i64,
        "token_type": "refresh"
    });
    let policy = VerificationPolicy::refresh_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .build()
        .unwrap();

    build_verifier()
        .verify_json_claims(&signed_value_token(id_header(), claims), &policy)
        .await
        .unwrap();
}

#[tokio::test]
async fn allocation_baseline_static_jwks_successful_verification() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(valid_claims());

    let report = measure_allocations_async("static_jwks_success", async {
        verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap();
    })
    .await;

    alloc_counter::emit_report(&report).expect("allocation report");
    assert!(report.allocation_count > 0);
}

#[tokio::test]
async fn allocation_baseline_remote_jwks_cache_hit_verification() {
    let verifier = build_remote_verifier(crate::jwks::CountingTransport::from_bodies(vec![
        crate::jwks::jwks(),
    ]));
    let policy = policy();
    let token = token(valid_claims());
    verifier
        .verify::<serde_json::Value>(&token, &policy)
        .await
        .unwrap();

    let report = measure_allocations_async("remote_jwks_cache_hit", async {
        verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap();
    })
    .await;

    alloc_counter::emit_report(&report).expect("allocation report");
    assert!(report.allocation_count > 0);
}

#[tokio::test]
async fn allocation_baseline_negative_malformed_token() {
    let verifier = build_verifier();
    let policy = policy();

    let report = measure_allocations_async("malformed_token", async {
        let error = verifier
            .verify::<serde_json::Value>("not-a-jwt", &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
    })
    .await;

    alloc_counter::emit_report(&report).expect("allocation report");
}

#[tokio::test]
async fn allocation_baseline_negative_wrong_audience() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.registered.aud = Some(crate::Audience::Single("wrong".to_owned()));
    let token = token(claims);
    let policy = policy();

    let report = measure_allocations_async("wrong_audience", async {
        let error = verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
    })
    .await;

    alloc_counter::emit_report(&report).expect("allocation report");
}

#[tokio::test]
async fn opt_loop_probe_cache_hit_verification_loop_completes() {
    let verifier = build_remote_verifier(crate::jwks::CountingTransport::from_bodies(vec![
        crate::jwks::jwks(),
    ]));
    let policy = policy();
    let token = token(valid_claims());
    verifier
        .verify::<serde_json::Value>(&token, &policy)
        .await
        .unwrap();

    opt_loop_probe::measure_future(async {
        for _ in 0..50 {
            verifier
                .verify::<serde_json::Value>(&token, &policy)
                .await
                .unwrap();
        }
    })
    .await;

    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[tokio::test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_jwt_decode_candidate_matrix_reports_allocations_and_cpu() {
    let static_verifier = build_verifier();
    let remote_verifier = build_remote_verifier(crate::jwks::CountingTransport::from_bodies(vec![
        crate::jwks::jwks(),
    ]));
    let policy = policy();
    let valid_token = token(valid_claims());
    let mut wrong_audience_claims = valid_claims();
    wrong_audience_claims.registered.aud = Some(crate::Audience::Single("wrong".to_owned()));
    let wrong_audience_token = token(wrong_audience_claims);

    remote_verifier
        .verify::<serde_json::Value>(&valid_token, &policy)
        .await
        .unwrap();

    let static_async_json = measure_allocations_async("matrix_static_async_json", async {
        for _ in 0..100 {
            static_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let static_sync_json = measure_allocations("matrix_static_sync_json", || {
        for _ in 0..100 {
            static_verifier
                .verify_static::<serde_json::Value>(&valid_token, &policy)
                .unwrap();
        }
    });
    let static_async_typed = measure_allocations_async("matrix_static_async_typed", async {
        for _ in 0..100 {
            static_verifier
                .verify::<crate::jwks::Claims>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let remote_async_json =
        measure_allocations_async("matrix_remote_cache_hit_async_json", async {
            for _ in 0..100 {
                remote_verifier
                    .verify::<serde_json::Value>(&valid_token, &policy)
                    .await
                    .unwrap();
            }
        })
        .await;
    let malformed = measure_allocations_async("matrix_malformed_token", async {
        for _ in 0..100 {
            let error = static_verifier
                .verify::<serde_json::Value>("not-a-jwt", &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
        }
    })
    .await;
    let wrong_audience = measure_allocations_async("matrix_wrong_audience", async {
        for _ in 0..100 {
            let error = static_verifier
                .verify::<serde_json::Value>(&wrong_audience_token, &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
        }
    })
    .await;

    for report in [
        static_async_json,
        static_sync_json,
        static_async_typed,
        remote_async_json,
        malformed,
        wrong_audience,
    ] {
        alloc_counter::emit_report(&report).expect("allocation report");
    }

    let static_async_json_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            static_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let static_sync_json_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            static_verifier
                .verify_static::<serde_json::Value>(&valid_token, &policy)
                .unwrap();
        }
    });
    let static_async_typed_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            static_verifier
                .verify::<crate::jwks::Claims>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let remote_async_json_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            remote_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let malformed_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            let error = static_verifier
                .verify::<serde_json::Value>("not-a-jwt", &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
        }
    })
    .await;
    let wrong_audience_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            let error = static_verifier
                .verify::<serde_json::Value>(&wrong_audience_token, &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
        }
    })
    .await;

    println!(
        "jwt_decode_candidate_matrix_cpu_ns static_async_json={} static_sync_json={} \
         static_async_typed={} remote_cache_hit_async_json={} malformed={} wrong_audience={}",
        static_async_json_cpu.as_nanos(),
        static_sync_json_cpu.as_nanos(),
        static_async_typed_cpu.as_nanos(),
        remote_async_json_cpu.as_nanos(),
        malformed_cpu.as_nanos(),
        wrong_audience_cpu.as_nanos()
    );
}

fn measure_allocations(label: &'static str, run: impl FnOnce()) -> AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
}

async fn measure_allocations_async(
    label: &'static str,
    run: impl Future<Output = ()>,
) -> AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run.await;
    guard.finish()
}

fn best_of_three(mut run: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        run();
        best = best.min(started.elapsed());
    }
    best
}

async fn best_of_three_async<Fut>(mut run: impl FnMut() -> Fut) -> Duration
where Fut: Future<Output = ()> {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        run().await;
        best = best.min(started.elapsed());
    }
    best
}

#[test]
fn given_mutated_hmac_token_when_verifying_then_decision_oracle_holds() {
    // Given a valid HMAC seed token. This is the deterministic twin of the
    // `jwt_decision` fuzz oracle: only the byte-identical seed may verify.
    let verifier = build_hmac_verifier();
    let seed = hmac_token(valid_claims());
    verifier
        .verify_static_json_claims_only(&seed, &policy())
        .expect("seed must verify");
    let (header, rest) = seed.split_once('.').expect("seed header");
    let (payload, signature) = rest.split_once('.').expect("seed payload");
    let mutated = [
        // Flipped signature character.
        format!("{header}.{payload}.{}", flip_first_character(signature)),
        // Algorithm-confusion header.
        format!(
            "{}.{payload}.{signature}",
            base64_url_encode(br#"{"alg":"none","kid":"hmac-key","typ":"at+jwt"}"#)
        ),
        // Duplicated claim in the payload.
        format!(
            "{header}.{}.{}",
            base64_url_encode(
                format!(
                    "{},\"client_id\":\"mallory\"}}",
                    serde_json::to_string(&valid_claims())
                        .expect("claims serialize")
                        .trim_end_matches('}')
                )
                .as_bytes()
            ),
            signature
        ),
        // Dropped signature segment.
        format!("{header}.{payload}."),
        // Expired lifetime with the original signature.
        format!(
            "{header}.{}.{}",
            base64_url_encode(
                serde_json::to_string(&valid_claims())
                    .expect("claims serialize")
                    .replace("1700000300", "1000")
                    .as_bytes()
            ),
            signature
        ),
        // Truncated serialization.
        seed.get(..seed.len() / 2)
            .expect("base64url seed; midpoint is a character boundary")
            .to_string(),
        // Trailing fourth segment.
        format!("{seed}.e30"),
    ];

    // When each mutated token reaches the symmetric verifier.
    for token in mutated {
        // Then every mutation fails closed.
        assert!(
            verifier
                .verify_static_json_claims_only(&token, &policy())
                .is_err(),
            "mutated token verified: {token}"
        );
    }
}

fn flip_first_character(segment: &str) -> String {
    let mut characters: Vec<char> = segment.chars().collect();
    if characters.is_empty() {
        return String::new();
    }
    characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
    characters.into_iter().collect()
}

#[tokio::test]
async fn given_second_configured_audience_when_verifying_signed_tokens_then_each_entrypoint_accepts_it()
 {
    let verifier = build_verifier();
    let policy = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .audiences(["api-first", "api-second"])
        .unwrap()
        .build()
        .unwrap();
    for audience in [
        crate::Audience::Single("api-first".into()),
        crate::Audience::Single("api-second".into()),
        crate::Audience::Multiple(vec!["other".into(), "api-second".into()]),
    ] {
        let mut claims = valid_claims();
        claims.registered.aud = Some(audience);
        let token = token(claims);
        verifier.verify::<Claims>(&token, &policy).await.unwrap();
        verifier
            .verify_json_claims_only(&token, &policy)
            .await
            .unwrap();
        verifier.verify_static::<Claims>(&token, &policy).unwrap();
        verifier
            .verify_static_json_claims_only(&token, &policy)
            .unwrap();
    }
}

#[test]
fn given_multiple_allowed_audiences_when_specialized_tokens_are_verified_then_actual_aud_count_controls_client_checks()
 {
    for kind in [TokenKind::Access, TokenKind::Id, TokenKind::Refresh] {
        let builder = match kind {
            TokenKind::Access => VerificationPolicy::access_token(),
            TokenKind::Id => VerificationPolicy::id_token(),
            TokenKind::Refresh => VerificationPolicy::refresh_token(),
        };
        let policy = builder
            .issuer("https://issuer.example")
            .unwrap()
            .audiences(["other-allowed", "aux-api"])
            .unwrap()
            .client_id("client-123")
            .unwrap()
            .build()
            .unwrap();
        let verifier = build_verifier();
        let mut claims = serde_json::to_value(valid_claims()).unwrap();
        claims["token_type"] = serde_json::to_value(kind).unwrap();
        let header = if kind == TokenKind::Access {
            let mut header = id_header();
            header.typ = Some("at+jwt".into());
            header
        } else {
            id_header()
        };
        assert_actual_audience_client_checks(&verifier, &policy, header, claims);
    }
}

fn assert_actual_audience_client_checks(
    verifier: &JwtVerifier,
    policy: &VerificationPolicy,
    header: Header,
    mut claims: serde_json::Value,
) {
    let signed = signed_value_token(header.clone(), claims.clone());
    verifier
        .verify_static_json_claims_only(&signed, policy)
        .unwrap();
    claims["aud"] = json!(["other", "aux-api"]);
    let signed = signed_value_token(header.clone(), claims.clone());
    assert_client_mismatch(verifier, policy, &signed);
    claims["azp"] = json!("client-123");
    verifier
        .verify_static_json_claims_only(&signed_value_token(header.clone(), claims.clone()), policy)
        .unwrap();
    claims["azp"] = json!("wrong");
    assert_client_mismatch(
        verifier,
        policy,
        &signed_value_token(header.clone(), claims.clone()),
    );
    claims["azp"] = json!("client-123");
    claims["client_id"] = json!("wrong");
    assert_client_mismatch(verifier, policy, &signed_value_token(header, claims));
}

fn assert_client_mismatch(verifier: &JwtVerifier, policy: &VerificationPolicy, token: &str) {
    assert_eq!(
        verifier
            .verify_static_json_claims_only(token, policy)
            .unwrap_err()
            .kind(),
        &JwtDecodeErrorKind::ClientMismatch
    );
}
