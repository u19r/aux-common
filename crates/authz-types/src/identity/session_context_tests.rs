use crate::SessionContext;

#[test]
fn future_auth_and_mfa_timestamps_are_not_recent() {
    let session = SessionContext::with_mfa(1_001, 1_001, "otp");

    assert!(!session.is_auth_recent_at(1_000, 300));
    assert!(!session.is_mfa_recent_at(1_000, 300));
}

#[test]
fn recency_at_exact_boundary_is_accepted() {
    let session = SessionContext::with_mfa(700, 700, "otp");

    assert!(session.is_auth_recent_at(1_000, 300));
    assert!(session.is_mfa_recent_at(1_000, 300));
}
