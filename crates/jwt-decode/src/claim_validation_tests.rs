use jsonwebtoken::{Algorithm, Header};
use serde_json::json;

use crate::{
    JwtDecodeErrorKind,
    test_support::{
        Claims, build_verifier, policy, registered_claims, signed_value_token, token, valid_claims,
    },
};

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
