use super::*;

#[test]
fn expiration_at_exact_second_is_expired() {
    let token = TokenContext {
        token_id: "token".to_string(),
        owner_id: "owner".to_string(),
        subject_binding: TokenSubjectBinding::Subject,
        scopes: TokenScopeConfig::default(),
        expires_at: Some(1_000),
    };

    assert!(token.is_expired_at(1_000));
    assert!(!token.is_expired_at(999));
}
