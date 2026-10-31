use std::time::Duration;

use super::VerificationPolicy;
#[test]
fn canonical_access_token_leeway_cannot_exceed_transition_bound() {
    for (seconds, accepted) in [(0, true), (60, true), (61, false)] {
        let result = VerificationPolicy::access_token()
            .issuer("https://issuer.example")
            .unwrap()
            .audience("resource")
            .unwrap()
            .token_type_value("access_token")
            .leeway(Duration::from_secs(seconds))
            .build();
        assert_eq!(result.is_ok(), accepted);
    }
}
#[test]
fn fractional_leeway_cannot_exceed_the_whole_second_transition_bound() {
    assert!(
        VerificationPolicy::access_token()
            .issuer("https://issuer.example")
            .unwrap()
            .audience("resource")
            .unwrap()
            .token_type_value("access_token")
            .leeway(Duration::from_secs(60) + Duration::from_nanos(1))
            .build()
            .is_err()
    );
}

/// The standard `access_token()` preset carries the `access` token-type claim
/// value and is the intended DPoP-bound access-token policy, so the documented
/// `MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS` ceiling must apply to it too.
/// Before this regression, only the `access_token` claim-value convention
/// enforced the ceiling and the ceiling was silent dead code for the preset.
#[test]
fn standard_access_preset_leeway_cannot_exceed_dpop_transition_bound() {
    for (seconds, accepted) in [(60, true), (61, false), (3600, false)] {
        let result = VerificationPolicy::access_token()
            .issuer("https://issuer.example")
            .unwrap()
            .audience("resource")
            .unwrap()
            .leeway(Duration::from_secs(seconds))
            .build();
        assert_eq!(
            result.is_ok(),
            accepted,
            "preset leeway {seconds}s unexpectedly {}",
            if accepted { "rejected" } else { "accepted" }
        );
    }
}

/// Generic (non-OAuth) JWT policies intentionally keep free leeway: they are
/// not DPoP-bound access-token policies.
#[test]
fn generic_jwt_policy_keeps_unbounded_leeway() {
    let result = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("resource")
        .unwrap()
        .leeway(Duration::from_secs(3600))
        .build();
    assert!(result.is_ok());
}
