use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_request::{HttpClientBuilder, HttpRequestError, Transport, TransportFuture};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use tokio::sync::Notify;

use crate::{
    AllowedAlgorithms, JwksCachePolicy, JwksDocument, JwksSource, JwksUrl, JwtDecodeErrorKind,
    JwtVerifier, RemoteJwksSource, SignatureAlgorithm, TokenKind, VerificationPolicy,
    test_support::{
        Claims, CountingTransport, FixedClock, build_remote_verifier,
        build_remote_verifier_with_policy, build_verifier, id_header, jwk, jwks,
        jwks_without_test_key, mock_response, policy, registered_claims, signed_raw_token,
        signed_token, signed_value_token, token, token_without_iat, valid_claims,
    },
};

#[derive(Debug)]
struct InvalidationRaceTransport {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    first_started: Arc<Notify>,
    release_first: Arc<Notify>,
}

impl Transport for InvalidationRaceTransport {
    fn send(&self, _request: http_request::reqwest::Request) -> TransportFuture {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let first_started = Arc::clone(&self.first_started);
        let release_first = Arc::clone(&self.release_first);
        Box::pin(async move {
            if call == 0 {
                first_started.notify_one();
                release_first.notified().await;
                Ok(mock_response(jwks_without_test_key()))
            } else {
                Ok(mock_response(jwks()))
            }
        })
    }
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

#[test]
fn given_trailing_json_in_jwks_when_parsing_then_rejects_document() {
    let error = JwksDocument::from_json_str(&format!("{} {{}}", jwks())).unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksParse);
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
async fn given_remote_jwks_when_verifying_twice_then_second_verify_uses_cache() {
    let transport = CountingTransport::from_bodies(vec![jwks()]);
    let attempts = Arc::clone(&transport.attempts);
    let verifier = build_remote_verifier(transport);

    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap();
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap();

    assert_eq!(1, attempts.load(Ordering::SeqCst));
}

#[tokio::test]
async fn given_remote_jwks_rotation_when_kid_unknown_then_forced_refresh_accepts_new_key() {
    let transport = CountingTransport::from_bodies(vec![jwks_without_test_key(), jwks()]);
    let attempts = Arc::clone(&transport.attempts);
    let verifier = build_remote_verifier(transport);

    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap();

    assert_eq!(2, attempts.load(Ordering::SeqCst));
}

#[tokio::test]
async fn given_repeated_unknown_kids_when_verifying_then_refreshes_are_bounded() {
    let transport = CountingTransport::from_bodies(vec![jwks(), jwks_without_test_key()]);
    let attempts = Arc::clone(&transport.attempts);
    let verifier = build_remote_verifier(transport);
    let claims = serde_json::to_vec(&valid_claims()).expect("claims");

    for kid in ["unknown-one", "unknown-two", "unknown-three"] {
        let header = format!("{{\"alg\":\"RS256\",\"kid\":\"{kid}\",\"typ\":\"at+jwt\"}}");
        let token = signed_raw_token(header.as_bytes(), &claims);
        let error = verifier
            .verify::<Claims>(&token, &policy())
            .await
            .expect_err("unknown key id must remain invalid");
        assert_eq!(error.kind(), &JwtDecodeErrorKind::KeyNotFound);
    }

    assert_eq!(2, attempts.load(Ordering::SeqCst));
}

#[tokio::test]
async fn given_stale_remote_jwks_when_refresh_fails_then_stale_value_is_used() {
    let transport = CountingTransport::from_results(vec![
        Ok(mock_response(jwks())),
        Err(HttpRequestError::Decode),
    ]);
    let attempts = Arc::clone(&transport.attempts);
    let verifier = build_remote_verifier_with_policy(
        transport,
        JwksCachePolicy {
            fallback_ttl: Duration::from_millis(5),
            stale_ttl: Duration::from_secs(5),
            stale_on_fetch_error: true,
            ..JwksCachePolicy::default()
        },
    );

    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap();

    assert_eq!(2, attempts.load(Ordering::SeqCst));
}

#[tokio::test]
async fn given_default_remote_jwks_policy_when_refresh_fails_then_rejects_stale_value() {
    let transport = CountingTransport::from_results(vec![
        Ok(mock_response(jwks())),
        Err(HttpRequestError::Decode),
    ]);
    let attempts = Arc::clone(&transport.attempts);
    let verifier = build_remote_verifier_with_policy(
        transport,
        JwksCachePolicy {
            fallback_ttl: Duration::from_millis(5),
            ..JwksCachePolicy::default()
        },
    );

    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect("initial JWKS fetch should succeed");
    tokio::time::sleep(Duration::from_millis(10)).await;
    let error = verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect_err("default policy must fail closed when refresh fails");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
    assert_eq!(2, attempts.load(Ordering::SeqCst));
}

#[tokio::test]
async fn given_invalidation_during_a_jwks_fetch_when_fetch_completes_then_old_document_is_not_reused()
 {
    let transport = InvalidationRaceTransport {
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        first_started: Arc::new(Notify::new()),
        release_first: Arc::new(Notify::new()),
    };
    let first_started = Arc::clone(&transport.first_started);
    let release_first = Arc::clone(&transport.release_first);
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("build test HTTP client");
    let source = JwksSource::Url(Box::new(RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").expect("JWKS URL"),
        JwksCachePolicy::default(),
        client,
    )));

    let first_source = source.clone();
    let first = tokio::spawn(async move {
        first_source
            .document_for_issuer("https://issuer.example")
            .await
            .expect("first fetch")
    });
    first_started.notified().await;
    source.invalidate_issuer("https://issuer.example");

    let second = tokio::time::timeout(
        Duration::from_secs(1),
        source.document_for_issuer("https://issuer.example"),
    )
    .await
    .expect("generation change must not wait for the invalidated fetch")
    .expect("second fetch");
    release_first.notify_one();
    let first = first.await.expect("first fetch task");

    assert!(
        !Arc::ptr_eq(&first, &second),
        "an invalidated in-flight document must not be reused"
    );
}

#[test]
fn given_oversized_or_key_flooded_jwks_when_parsing_then_rejects_document() {
    let oversized = " ".repeat(crate::jwks::MAX_JWKS_DOCUMENT_BYTES + 1);
    assert_eq!(
        JwksDocument::from_json_str(&oversized)
            .expect_err("oversized JWKS must be rejected")
            .kind(),
        &JwtDecodeErrorKind::JwksParse
    );

    let template = serde_json::to_value(jwk()).expect("JWK JSON");
    let keys = (0..=crate::jwks::MAX_JWKS_KEYS)
        .map(|index| {
            let mut key = template.clone();
            key["kid"] = Value::String(format!("key-{index}"));
            key
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({ "keys": keys }).to_string();
    assert_eq!(
        JwksDocument::from_json_str(&document)
            .expect_err("JWKS key floods must be rejected")
            .kind(),
        &JwtDecodeErrorKind::JwksParse
    );
}

#[test]
fn given_http_remote_jwks_url_when_using_secure_constructor_then_rejects_insecure_url() {
    let error = JwksUrl::parse_https("http://issuer.example/jwks.json").unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
}

#[test]
fn given_secret_bearing_jwks_url_when_debugging_or_parsing_then_redacts_and_rejects() {
    let value = "https://user:password@issuer.example/jwks.json?secret=query-sentinel#fragment";
    let parsed = JwksUrl::parse_https(value);
    assert!(
        parsed.is_err(),
        "secure JWKS URLs must not accept secret components"
    );

    let parsed_for_debug = JwksUrl::parse_for_tests(value).expect("test URL should parse");
    let debug = format!("{parsed_for_debug:?}");
    assert!(!debug.contains("password"));
    assert!(!debug.contains("query-sentinel"));
}

#[test]
fn given_static_symmetric_jwks_when_debugging_then_hmac_material_is_redacted() {
    let secret = "bG9jYWwgdGVzdCBobWFjIHNlY3JldCB3aXRoIGVub3VnaCBlbnRyb3B5";
    let source = JwksSource::json_string(
        serde_json::json!({
            "keys": [{
                "kty": "oct",
                "kid": "hmac-key",
                "alg": "HS256",
                "k": secret
            }]
        })
        .to_string(),
    )
    .expect("static HMAC JWK");

    let debug = format!("{source:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains("local test hmac secret"));
}

#[test]
fn given_short_local_hmac_secret_when_constructing_source_then_rejects_and_keeps_strong_secret() {
    assert!(
        JwksSource::local_symmetric_key("weak", b"short".to_vec()).is_err(),
        "a guessable HMAC secret must not be accepted"
    );
    assert!(
        JwksSource::local_symmetric_key("strong", [0x42; 32].to_vec()).is_ok(),
        "a 256-bit HMAC secret remains supported"
    );
}

#[tokio::test]
async fn given_hs512_with_a_256_bit_local_secret_when_verifying_then_rejects_key() {
    let secret = [0x42; 32];
    let source = JwksSource::local_symmetric_key("hs512", secret.to_vec())
        .expect("the baseline local secret is valid for HS256");
    let verifier = JwtVerifier::builder()
        .jwks_source(source)
        .allowed_algorithms(AllowedAlgorithms::symmetric([SignatureAlgorithm::HS512]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some("hs512".to_owned());
    header.typ = Some("at+jwt".to_owned());
    let token = jsonwebtoken::encode(&header, &valid_claims(), &EncodingKey::from_secret(&secret))
        .expect("test token");

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .expect_err("HS512 must require a 512-bit local secret");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}
