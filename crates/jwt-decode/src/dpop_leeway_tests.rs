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
