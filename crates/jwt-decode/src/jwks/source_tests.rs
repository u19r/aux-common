use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use http_request::{
    HttpClientBuilder, HttpRequestError, HttpResponse, StatusCode, Transport, TransportFuture, Url,
    header::HeaderMap,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::Value;
use tokio::sync::Notify;

use super::{
    JwksDocument, JwksSource, MAX_INVALIDATION_GENERATIONS, MAX_UNKNOWN_KID_REFRESH_COOLDOWNS,
    RemoteJwksSource,
};
use crate::{
    AllowedAlgorithms, JwksCachePolicy, JwksUrl, JwtDecodeErrorKind, JwtVerifier,
    SignatureAlgorithm,
    jwks::{
        Claims, CountingTransport, FixedClock, HMAC_SECRET, build_hmac_verifier,
        build_remote_verifier, build_remote_verifier_with_policy, jwk, jwks, jwks_without_test_key,
        mock_response, policy, signed_raw_token, token, valid_claims,
    },
};

#[test]
fn given_malformed_empty_or_blank_id_jwks_when_parsing_then_rejects_document() {
    // Given malformed, empty, and blank-key-id documents at the public parser
    // boundary.
    let malformed = JwksDocument::from_json_str("{").expect_err("malformed JSON must fail");
    let empty = JwksDocument::from_json_str(r#"{"keys":[]}"#).expect_err("an empty JWKS must fail");
    let mut blank_id: Value = serde_json::from_str(&jwks()).expect("valid fixture JSON");
    blank_id["keys"][0]["kid"] = Value::String(String::new());

    // When each document is parsed, validation rejects it before use.
    let blank_id =
        JwksDocument::from_json_str(&blank_id.to_string()).expect_err("a blank key id must fail");

    // Then each failure is classified as a key-document or key-material error.
    assert_eq!(malformed.kind(), &JwtDecodeErrorKind::JwksParse);
    assert_eq!(empty.kind(), &JwtDecodeErrorKind::JwksParse);
    assert_eq!(blank_id.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_valid_jwks_when_debugged_then_reports_only_key_count() {
    // Given a parsed public key document containing a material sentinel.
    let mut value: Value = serde_json::from_str(&jwks()).expect("valid fixture JSON");
    value["keys"][0]["kid"] = Value::String("jwk-material-sentinel".to_owned());
    let document = JwksDocument::from_json_str(&value.to_string()).expect("fixture JWKS");

    // When its diagnostic representation is rendered, it reports bounded
    // metadata.
    let debug = format!("{document:?}");

    // Then diagnostics use the exact whitelisted shape and omit key material.
    assert_eq!(debug, "JwksDocument { key_count: 1, .. }");
    assert!(!debug.contains("jwk-material-sentinel"));
}

#[test]
fn given_trailing_json_in_jwks_when_parsing_then_rejects_document() {
    let error = JwksDocument::from_json_str(&format!("{} {{}}", jwks())).unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksParse);
}

#[test]
fn given_source_variants_when_debugged_then_redacts_key_and_url_material() {
    // Given a local symmetric key and a remote source with a test-only
    // transport.
    let local_secret = b"local-secret-sentinel-0123456789";
    let local = JwksSource::local_symmetric_key("local-key", local_secret.to_vec())
        .expect("strong local key");
    let local_source_debug = format!("{local:?}");
    let JwksSource::LocalSymmetric(local_key) = local else {
        panic!("constructor must create a local symmetric source");
    };
    let local_debug = format!("{local_key:?}");

    let transport = CountingTransport::from_bodies(Vec::new());
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("test HTTP client");
    let remote = RemoteJwksSource::new(
        JwksUrl::parse_https("https://jwks-url-secret-sentinel.example/jwks.json")
            .expect("HTTPS URL"),
        JwksCachePolicy::default(),
        client,
    );
    let remote_debug = format!("{remote:?}");
    let remote_source_debug = format!("{:?}", JwksSource::Url(Box::new(remote)));

    // When the public debug representations are rendered, secrets and URLs stay
    // hidden.
    assert_eq!(
        local_source_debug,
        "JwksSource { kind: \"local_symmetric\", .. }"
    );
    assert_eq!(
        local_debug,
        "LocalSymmetricKey { key_id: \"local-key\", .. }"
    );
    assert!(!local_debug.contains(std::str::from_utf8(local_secret).unwrap()));
    assert!(remote_debug.contains("RemoteJwksSource"));
    assert!(remote_debug.contains("policy"));
    assert!(remote_debug.contains("[REDACTED]"));
    assert!(!remote_debug.contains("jwks-url-secret-sentinel"));
    assert_eq!(
        remote_source_debug,
        "JwksSource { kind: \"remote_url\", .. }"
    );
}

#[test]
fn given_valid_https_jwks_url_when_constructing_source_then_creates_remote_source() {
    // Given a valid HTTPS JWKS endpoint.
    let source = JwksSource::url("https://jwks-url-secret-sentinel.example/jwks.json")
        .expect("secure URL should construct a source");
    let source_debug = format!("{source:?}");

    // When the public constructor returns, it selects the remote source
    // variant.
    assert!(matches!(&source, JwksSource::Url(_)));
    assert!(source_debug.contains("remote_url"));

    let static_source = JwksSource::json_string(jwks()).expect("static JWKS");
    assert!(matches!(static_source, JwksSource::Jwks(_)));

    // Then malformed URLs remain rejected by the secure URL parser.
    let error = JwksUrl::parse_https("not a URL").expect_err("malformed URL must fail");
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
}

#[tokio::test]
async fn given_local_symmetric_source_when_asymmetric_verification_is_requested_then_rejects_key() {
    // Given a local HMAC source and an RSA token that cannot use it.
    let verifier = JwtVerifier::builder()
        .jwks_source(
            JwksSource::local_symmetric_key("local-key", HMAC_SECRET.to_vec())
                .expect("strong local key"),
        )
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .expect("verifier");

    // When both async and static public verification paths resolve the source,
    // they fail closed.
    let error = verifier
        .verify_json_claims_only(&token(valid_claims()), &policy())
        .await
        .expect_err("symmetric source must not serve an RSA key");
    let static_error = verifier
        .verify_static_json_claims_only(&token(valid_claims()), &policy())
        .expect_err("symmetric source must not serve a static RSA key");

    // Then neither path discloses or accepts incompatible key material.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    assert_eq!(static_error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[tokio::test]
async fn given_local_symmetric_source_when_kid_is_unknown_then_rejects_selection() {
    // Given a valid HMAC token carrying an unknown key id.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("unknown-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    let token = jsonwebtoken::encode(
        &header,
        &valid_claims(),
        &EncodingKey::from_secret(HMAC_SECRET),
    )
    .expect("test token");

    // When the local source performs key selection, it rejects the unknown id.
    let error = build_hmac_verifier()
        .verify_json_claims_only(&token, &policy())
        .await
        .expect_err("unknown local key id must fail");

    // Then the caller receives a non-sensitive selection error.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::KeyNotFound);
}

#[tokio::test]
async fn given_local_symmetric_hs384_source_when_token_is_valid_then_accepts_signature() {
    // Given a local 384-bit HMAC key and a matching HS384 token.
    let secret = [0x42; 48];
    let mut header = Header::new(Algorithm::HS384);
    header.kid = Some("hmac-384".to_owned());
    header.typ = Some("at+jwt".to_owned());
    let token = jsonwebtoken::encode(&header, &valid_claims(), &EncodingKey::from_secret(&secret))
        .expect("test token");
    let verifier = JwtVerifier::builder()
        .jwks_source(
            JwksSource::local_symmetric_key("hmac-384", secret.to_vec()).expect("strong local key"),
        )
        .allowed_algorithms(AllowedAlgorithms::symmetric([SignatureAlgorithm::HS384]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .expect("verifier");

    // When the public verifier validates the token, it applies the HS384
    // key-size rule.
    verifier
        .verify_json_claims_only(&token, &policy())
        .await
        .expect("HS384 signature should verify");
}

#[test]
fn given_remote_source_when_static_verification_is_requested_then_rejects_fetch() {
    // Given a remote source that must never be used by the static-only path.
    let verifier = build_remote_verifier_with_policy(
        CountingTransport::from_bodies(Vec::new()),
        JwksCachePolicy::default(),
    );

    // When static verification asks for its document, the remote boundary is
    // unavailable.
    let error = verifier
        .verify_static_json_claims_only(&token(valid_claims()), &policy())
        .expect_err("static verification must not fetch remote keys");

    // Then the failure is classified as a JWKS fetch policy error.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
}

#[tokio::test]
async fn given_remote_jwks_when_response_is_malformed_then_rejects_document() {
    // Given a successful HTTP response whose body is not a JWKS document.
    let transport = CountingTransport::from_results(vec![Ok(mock_response("{".to_owned()))]);
    let verifier = build_remote_verifier_with_policy(transport, JwksCachePolicy::default());

    // When remote verification parses the body, document validation fails
    // closed.
    let error = verifier
        .verify_json_claims_only(&token(valid_claims()), &policy())
        .await
        .expect_err("malformed remote JWKS must fail");

    // Then malformed remote content is not treated as a usable key set.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksParse);
}

#[tokio::test]
async fn given_remote_jwks_when_response_is_non_success_then_rejects_fetch() {
    // Given a non-success HTTP response from the JWKS endpoint.
    let response = HttpResponse::from_mock(
        StatusCode::BAD_REQUEST,
        HeaderMap::new(),
        b"bad response".to_vec(),
        Url::parse("https://issuer.example/jwks.json").expect("fixture URL"),
    );
    let transport = CountingTransport::from_results(vec![Ok(response)]);
    let verifier = build_remote_verifier_with_policy(transport, JwksCachePolicy::default());

    // When the remote source checks HTTP status, it refuses the response.
    let error = verifier
        .verify_json_claims_only(&token(valid_claims()), &policy())
        .await
        .expect_err("non-success JWKS response must fail");

    // Then transport details are normalized to a fetch error.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
}

#[tokio::test]
async fn given_remote_jwks_when_body_exceeds_policy_then_rejects_fetch() {
    // Given an otherwise successful response larger than the configured body
    // budget.
    let response = mock_response("oversized".to_owned());
    let transport = CountingTransport::from_results(vec![Ok(response)]);
    let verifier = build_remote_verifier_with_policy(
        transport,
        JwksCachePolicy {
            max_body_size: 1,
            ..JwksCachePolicy::default()
        },
    );

    // When the remote client applies the body limit, it rejects the response
    // before parsing.
    let error = verifier
        .verify_json_claims_only(&token(valid_claims()), &policy())
        .await
        .expect_err("oversized JWKS response must fail");

    // Then oversized untrusted input is classified as a fetch error.
    assert_eq!(error.kind(), &JwtDecodeErrorKind::JwksFetch);
}

#[tokio::test]
async fn given_many_remote_issuer_invalidations_when_control_entry_is_cached_then_overflow_reclaims_generation()
 {
    // Given a control issuer whose document is cached before the ledger
    // overflows.
    let transport = CountingTransport::from_bodies(vec![jwks(), jwks()]);
    let attempts = Arc::clone(&transport.attempts);
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("test HTTP client");
    let source = JwksSource::Url(Box::new(RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").expect("HTTPS URL"),
        JwksCachePolicy::default(),
        client,
    )));
    let control_issuer = "https://control.example";
    let first = source
        .document_for_issuer(control_issuer)
        .await
        .expect("control document should be prefetched");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);

    // When distinct issuers cross the owning bound, old generations are
    // reclaimed.
    for index in 0..=MAX_INVALIDATION_GENERATIONS {
        source.invalidate_issuer(&format!("https://issuer-{index}.example"));
    }

    // Then the control issuer receives a new generation and must fetch again.
    let second = source
        .document_for_issuer(control_issuer)
        .await
        .expect("control document should refresh after reclamation");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(!Arc::ptr_eq(&first, &second));
}

#[test]
fn given_many_unknown_remote_issuers_when_refreshing_then_cooldown_state_is_bounded() {
    // Given a remote source whose owner stores refresh cooldowns in a bounded
    // map.
    let client = HttpClientBuilder::new()
        .with_transport(CountingTransport::from_bodies(Vec::new()))
        .build()
        .expect("test HTTP client");
    let remote = RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").expect("HTTPS URL"),
        JwksCachePolicy::default(),
        client,
    );

    // When the source owner sees more distinct issuers than its bound, it
    // reclaims old entries.
    for index in 0..=MAX_UNKNOWN_KID_REFRESH_COOLDOWNS {
        assert!(remote.test_allow_unknown_kid_refresh(&format!("https://issuer-{index}.example")));
    }

    // Then the private owner map remains bounded and its newest cooldown is
    // enforced.
    let newest = format!(
        "https://issuer-{}.example",
        MAX_UNKNOWN_KID_REFRESH_COOLDOWNS
    );
    assert!(!remote.test_allow_unknown_kid_refresh(&newest));
    let refresh_count = remote.unknown_kid_refresh_count();
    assert_eq!(refresh_count, 1);
    assert!(refresh_count <= MAX_UNKNOWN_KID_REFRESH_COOLDOWNS);
}

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
    let first = tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .expect("invalidation cancels the old fetch without provider release")
        .expect("first fetch task")
        .expect_err("invalidated fetch must fail closed");
    assert_eq!(first.kind(), &JwtDecodeErrorKind::JwksCache);
    let current = source
        .document_for_issuer("https://issuer.example")
        .await
        .expect("current document");
    assert!(
        Arc::ptr_eq(&current, &second),
        "the new generation must remain current"
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

#[tokio::test]
async fn given_rotation_cache_invalidation_and_unknown_kid_when_scripted_then_fetch_counts_match() {
    // Given a remote source whose first document predates rotation, driving
    // a scripted rotation, cache-hit, invalidation, and unknown-key timeline.
    let transport =
        CountingTransport::from_bodies(vec![jwks_without_test_key(), jwks(), jwks(), jwks()]);
    let attempts = Arc::clone(&transport.attempts);
    let http_client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("test HTTP client");
    let source = JwksSource::Url(Box::new(RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").expect("JWKS URL"),
        JwksCachePolicy::default(),
        http_client,
    )));
    let verifier = JwtVerifier::builder()
        .jwks_source(source.clone())
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();
    let fetches = || attempts.load(Ordering::SeqCst);

    // Rotation: the first verify forces exactly one refresh onto the new key.
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect("rotated key verifies after refresh");
    assert_eq!(fetches(), 2);

    // Cache hit: the rotated document serves without another fetch.
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect("cached key verifies");
    assert_eq!(fetches(), 2);

    // Compromise response: invalidation forces exactly one refetch.
    source.invalidate_issuer("https://issuer.example");
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect("post-invalidation key verifies");
    assert_eq!(fetches(), 3);

    // Unknown key: rejection never mints trust, however the refresh budget
    // behaves, and the known key keeps verifying afterwards.
    let claims = serde_json::to_vec(&valid_claims()).expect("claims");
    let header = "{\"alg\":\"RS256\",\"kid\":\"unknown-key\",\"typ\":\"at+jwt\"}";
    let unknown = signed_raw_token(header.as_bytes(), &claims);
    let error = verifier
        .verify::<Claims>(&unknown, &policy())
        .await
        .expect_err("unknown key id must remain invalid");
    assert_eq!(error.kind(), &JwtDecodeErrorKind::KeyNotFound);
    verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .expect("known key still verifies after unknown-key rejection");
}
