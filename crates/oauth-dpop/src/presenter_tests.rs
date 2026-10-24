use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    AccessTokenConfirmation, DpopTargetUri, PresenterValidationInput, ResourceChallenge,
    test_support::ProofKey,
};

#[test]
fn given_bound_and_unbound_authority_when_presenting_then_accepts_only_the_matching_scheme_key_and_token_hash()
 {
    let key = ProofKey::from_seed(1);
    let other = ProofKey::from_seed(2);
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    let token = "exact.ascii.token";
    let claims = json!({"jti":"request", "htm":"GET", "htu":target.as_str(), "iat":1_800_000_000,
        "ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))});
    let proof = key.sign(&claims);
    let bound = AccessTokenConfirmation::Dpop {
        jkt: key.thumbprint(),
    };
    let absent = AccessTokenConfirmation::Absent;
    let unsupported = AccessTokenConfirmation::Unsupported;
    for (scheme, confirmation, proof, access_token, expected) in [
        ("Bearer", &absent, None, token, true),
        ("bearer", &absent, None, token, true),
        ("DPoP", &bound, Some(proof.as_str()), token, true),
        ("Bearer", &bound, None, token, false),
        ("DPoP", &absent, Some(proof.as_str()), token, false),
        ("DPoP", &bound, None, token, false),
        ("DPoP", &unsupported, Some(proof.as_str()), token, false),
        ("Bearer", &unsupported, None, token, false),
        ("DPoP", &bound, Some(proof.as_str()), "another.token", false),
    ] {
        assert_eq!(
            PresenterValidationInput {
                scheme,
                access_token,
                proof,
                method: "GET",
                target_uri: &target,
                confirmation,
                now_seconds: 1_800_000_000
            }
            .validate()
            .is_ok(),
            expected
        );
    }
    let wrong_key = other.sign(&claims);
    assert!(
        PresenterValidationInput {
            scheme: "DPoP",
            access_token: token,
            proof: Some(&wrong_key),
            method: "GET",
            target_uri: &target,
            confirmation: &bound,
            now_seconds: 1_800_000_000
        }
        .validate()
        .is_err()
    );
    let no_hash =
        key.sign(&json!({"jti":"request","htm":"GET","htu":target.as_str(),"iat":1_800_000_000}));
    assert!(
        PresenterValidationInput {
            scheme: "DPoP",
            access_token: token,
            proof: Some(&no_hash),
            method: "GET",
            target_uri: &target,
            confirmation: &bound,
            now_seconds: 1_800_000_000
        }
        .validate()
        .is_err()
    );
}

#[test]
fn given_confirmation_shapes_when_normalizing_then_never_converts_present_unsupported_or_malformed_authority_to_bearer()
 {
    let jkt = ProofKey::from_seed(1).thumbprint();
    assert_eq!(
        AccessTokenConfirmation::parse(None).unwrap(),
        AccessTokenConfirmation::Absent
    );
    assert_eq!(
        AccessTokenConfirmation::parse(Some(&json!({"future":"extension"}))).unwrap(),
        AccessTokenConfirmation::Unsupported
    );
    assert_eq!(
        AccessTokenConfirmation::parse(Some(&json!({"jkt":jkt.as_str(),"future":true}))).unwrap(),
        AccessTokenConfirmation::Dpop { jkt: jkt.clone() }
    );
    for value in [
        json!(null),
        json!("key"),
        json!([]),
        json!({"jkt":"invalid"}),
        json!({"jkt":jkt.as_str(),"jwk":{}}),
        json!({"jkt":jkt.as_str(),"x5t#S256":"other"}),
    ] {
        assert!(AccessTokenConfirmation::parse(Some(&value)).is_err());
    }
    assert!(
        !ResourceChallenge::MissingCredentials
            .render()
            .contains("error=")
    );
    assert!(
        ResourceChallenge::InvalidDpopProof
            .render()
            .contains("invalid_dpop_proof")
    );
    assert!(!ResourceChallenge::InvalidToken.render().contains("Proxy"));
}
