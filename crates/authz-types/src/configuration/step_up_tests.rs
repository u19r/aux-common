use crate::AcrLevel;

#[test]
fn given_native_assurance_claims_when_parsed_then_levels_preserve_issuer_strength() {
    for (value, expected) in [
        ("urn:auxfn:acr:pwd", AcrLevel::SingleFactor),
        ("urn:auxfn:acr:mfa", AcrLevel::MultiFactor),
        ("urn:auxfn:acr:phishing-resistant", AcrLevel::HardwareToken),
    ] {
        let context = crate::SessionContext::from_claims(&serde_json::json!({
            "acr":value,"amr":["pwd","otp"],"auth_time":1_700_000_000
        }))
        .expect("signed assurance claims");
        assert_eq!(context.acr, expected, "{value}");
        assert_eq!(context.auth_time, Some(1_700_000_000));
    }
    assert_eq!(AcrLevel::from_urn("urn:other:acr:mfa"), None);
    let unknown = crate::SessionContext::from_claims(&serde_json::json!({
        "acr":"urn:other:acr:mfa","amr":["pwd","otp"]
    }))
    .expect("unknown assurance stays explicit");
    assert!(!unknown.acr.satisfies(AcrLevel::MultiFactor));
    assert!(crate::SessionContext::from_claims(&serde_json::json!({"amr":["otp"]})).is_none());
}

#[test]
fn given_hardware_token_when_recent_auth_is_required_then_assurance_is_not_substituted() {
    assert!(!AcrLevel::HardwareToken.satisfies(AcrLevel::RecentAuth));
    assert!(AcrLevel::RecentAuth.satisfies(AcrLevel::RecentAuth));
}

#[test]
fn given_all_assurance_pairs_when_checking_satisfaction_then_rank_order_holds() {
    // Given the closed assurance ranking, pinned here as executable
    // specification so a reordered enum cannot silently widen access.
    // `RecentAuth` carries no assurance strength: it satisfies only itself
    // (and the empty `None` requirement, which needs no authentication).
    let rank = |level: AcrLevel| match level {
        AcrLevel::None | AcrLevel::RecentAuth => 0,
        AcrLevel::SingleFactor => 1,
        AcrLevel::MultiFactor => 2,
        AcrLevel::HardwareToken => 3,
    };
    let levels = [
        AcrLevel::None,
        AcrLevel::SingleFactor,
        AcrLevel::MultiFactor,
        AcrLevel::HardwareToken,
        AcrLevel::RecentAuth,
    ];

    // When every held/required pair is evaluated.
    for held in levels {
        for required in levels {
            // Then recent-auth matches only itself as a requirement, while
            // every other level satisfies exactly the requirements at or
            // below its rank.
            let expected = if required == AcrLevel::RecentAuth {
                held == AcrLevel::RecentAuth
            } else {
                rank(held) >= rank(required)
            };
            assert_eq!(
                held.satisfies(required),
                expected,
                "assurance pair diverged: held={held:?} required={required:?}"
            );
        }
    }
}

#[test]
fn given_recent_auth_when_hardware_is_required_then_satisfaction_fails_closed() {
    assert!(!AcrLevel::RecentAuth.satisfies(AcrLevel::HardwareToken));
    assert!(!AcrLevel::RecentAuth.satisfies(AcrLevel::MultiFactor));
    assert!(!AcrLevel::RecentAuth.satisfies(AcrLevel::SingleFactor));
    assert!(AcrLevel::RecentAuth.satisfies(AcrLevel::RecentAuth));
    assert!(AcrLevel::RecentAuth.satisfies(AcrLevel::None));
}
