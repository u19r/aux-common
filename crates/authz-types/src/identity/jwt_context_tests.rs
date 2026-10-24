use crate::JwtContext;

#[test]
fn jwt_context_completeness_is_derived_fail_closed() {
    let context = JwtContext {
        roles_complete: false,
        claims_complete: true,
        ..JwtContext::default()
    };

    assert!(!context.is_complete());
}

#[test]
fn given_projection_without_completeness_flags_when_deserialized_then_incomplete() {
    // Given a projection that carries roles but omits every completeness flag.
    let value = serde_json::json!({
        "roles": [{ "role_id": "reader", "scope": "global" }]
    });

    // When the trusted-boundary shape is reconstructed from that projection.
    let context: JwtContext = serde_json::from_value(value).expect("projection parses");

    // Then absence means absence of evidence: the context is incomplete and
    // grants no JWT roles.
    assert!(!context.is_complete());
    assert!(!JwtContext::default().is_complete());
    assert!(JwtContext::complete(Vec::new(), Vec::new(), context.roles.clone()).is_complete());
}

#[test]
fn jwt_context_collection_deserialization_is_bounded() {
    let oversized = serde_json::json!({
        "orgs": (0..=500).map(|index| serde_json::json!({"org_id": format!("org-{index}")})).collect::<Vec<_>>()
    });
    let error = serde_json::from_value::<JwtContext>(oversized)
        .expect_err("JWT organization claims must be bounded");
    assert!(error.to_string().contains("orgs exceeds maximum"));
}
