use proptest::prelude::*;

use super::{normalize_origin, parse_client_data};
use crate::{
    CrossOriginPolicy, RpPolicy, UserVerification, WebAuthnError,
    assertion::{CHALLENGE_B64, policy},
};

#[test]
fn given_policy_when_constructing_then_expected_origin_is_caller_owned() {
    assert_eq!(policy().expected_origin(), "https://example.test");
}

#[test]
fn given_non_loopback_http_origin_when_constructing_policy_then_reject() {
    assert!(matches!(
        RpPolicy::try_new(
            CHALLENGE_B64,
            "http://attacker.example",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

#[test]
fn given_loopback_http_origin_when_constructing_policy_then_accept() {
    for origin in [
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ] {
        assert!(
            RpPolicy::try_new(
                CHALLENGE_B64,
                origin,
                [0; 32],
                UserVerification::Preferred,
                CrossOriginPolicy::Disallowed,
            )
            .is_ok(),
            "loopback origin should be accepted: {origin}"
        );
    }
}

#[test]
fn given_private_or_non_loopback_http_origin_when_constructing_policy_then_reject() {
    for origin in [
        "http://10.0.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://0.0.0.0",
        "http://[::ffff:127.0.0.1]",
        "http://localhost.attacker.example",
    ] {
        assert!(
            RpPolicy::try_new(
                CHALLENGE_B64,
                origin,
                [0; 32],
                UserVerification::Preferred,
                CrossOriginPolicy::Disallowed,
            )
            .is_err(),
            "non-loopback HTTP origin should be rejected: {origin}"
        );
    }
}

#[test]
fn given_short_challenge_when_constructing_policy_then_reject() {
    // Fifteen zero bytes is canonical base64url but below WebAuthn's
    // required 16-byte challenge minimum.
    assert!(matches!(
        RpPolicy::try_new(
            "AAAAAAAAAAAAAAAAAAAA",
            "https://example.test",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

#[test]
fn given_duplicate_client_data_members_when_parsing_then_reject() {
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.test","crossOrigin":false}"#;
    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::ClientData)
    ));
}

#[test]
fn given_cross_origin_client_data_when_top_origin_is_not_allowlisted_then_reject() {
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.test","crossOrigin":true,"topOrigin":"https://parent.test"}"#;
    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_allowlisted_cross_origin_client_data_then_normalize_top_origin() {
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::AllowedOrigins(vec!["https://PARENT.test/".to_string()]),
    )
    .expect("valid cross-origin policy");
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://EXAMPLE.test/","crossOrigin":true,"topOrigin":"https://PARENT.test/"}"#;
    let client_data = parse_client_data(json, "webauthn.get", &policy).expect("client data");
    assert_eq!(client_data.origin, "https://example.test");
    assert_eq!(
        client_data.top_origin.as_deref(),
        Some("https://parent.test")
    );
}

#[test]
fn given_cross_origin_client_data_with_same_top_origin_then_reject() {
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::AllowedOrigins(vec!["https://example.test".to_string()]),
    )
    .expect("valid cross-origin policy");
    let json = br#"{"origin":"https://example.test","crossOrigin":true,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get","topOrigin":"https://example.test"}"#;

    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_remote_http_client_data_when_policy_is_secure_then_reject() {
    let json = br#"{"origin":"http://attacker.example","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#;

    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_loopback_http_client_data_when_policy_matches_then_accept() {
    let loopback_policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "http://LOCALHOST:3000/",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid loopback policy");
    let json = br#"{"origin":"http://localhost:3000/","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#;

    let parsed = parse_client_data(json, "webauthn.get", &loopback_policy)
        .expect("loopback client data should be accepted");
    assert_eq!(parsed.origin, "http://localhost:3000");
}

#[test]
fn given_oversized_expected_challenge_when_constructing_policy_then_reject_before_decode() {
    assert!(matches!(
        RpPolicy::try_new(
            "A".repeat(1 << 20),
            "https://example.test",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

fn origin_shape() -> impl Strategy<Value = String> {
    ("https?", "[a-z]{1,12}", prop::option::of("[a-z]{1,12}")).prop_map(
        |(scheme, host, subdomain)| match subdomain {
            Some(sub) => format!("{scheme}://{sub}.{host}.test"),
            None => format!("{scheme}://{host}.test"),
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn given_normalized_origin_when_normalizing_again_then_fixed_point_holds(
        origin in origin_shape(),
    ) {
        // Given an origin that normalizes successfully.
        let Some(normalized) = normalize_origin(&origin) else {
            return Ok(());
        };

        // When normalization runs on its own output.
        // Then normalization is a fixed point, so policy comparison cannot
        // drift between validation and ceremony time.
        prop_assert_eq!(normalize_origin(&normalized), Some(normalized));
    }

    #[test]
    fn given_distinct_origins_when_normalizing_then_collisions_are_rejected(
        first in origin_shape(),
        second in origin_shape(),
    ) {
        // Given two origins that differ as written.
        prop_assume!(first != second);
        let (Some(first_normalized), Some(second_normalized)) =
            (normalize_origin(&first), normalize_origin(&second))
        else {
            return Ok(());
        };

        // When both normalize successfully.
        // Then a collision is itself the finding: distinct origins must
        // never compare equal after normalization.
        prop_assert_ne!(
            first_normalized,
            second_normalized,
            "origin collision: {:?} and {:?}",
            first,
            second
        );
    }
}

#[test]
fn given_whatwg_confusable_origins_when_normalizing_then_equivalence_is_exact() {
    // Given spellings that WHATWG URL parsing erases: backslash separators,
    // case differences, and default ports.
    let pairs = [
        ("https://example.test", "https:\\\\example.test"),
        ("https://example.test", "HTTPS://example.test"),
        ("https://example.test:443", "https://example.test"),
    ];
    for (canonical, confusable) in pairs {
        assert_eq!(
            normalize_origin(canonical),
            normalize_origin(confusable),
            "confusable pair diverged: {canonical:?}"
        );
    }

    // A trailing dot is preserved rather than erased, so dotted and bare
    // spellings mismatch and fail closed. Browsers never emit trailing-dot
    // origins, so strictness here rejects nothing legitimate.
    assert_ne!(
        normalize_origin("https://example.test"),
        normalize_origin("https://example.test.")
    );

    // Distinct registrable domains must never merge through normalization.
    assert_ne!(
        normalize_origin("https://example.test"),
        normalize_origin("https://evil.test")
    );
    assert_ne!(
        normalize_origin("https://example.test"),
        normalize_origin("https://sub.example.test")
    );
    assert_ne!(
        normalize_origin("https://example.test"),
        normalize_origin("http://example.test")
    );
}
