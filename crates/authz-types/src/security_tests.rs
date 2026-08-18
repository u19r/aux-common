use crate::{
    AcrLevel, ApiBatchEvaluationRequest, BatchEvaluationRequest, JwtContext, PermissionId,
    RolePermission, Scope, SessionContext, TokenScopeConfig,
};

#[test]
fn permission_id_deserialization_rejects_invalid_shape() {
    let result = serde_json::from_value::<RolePermission>(serde_json::json!({
        "permission_id": "invalid",
        "scopes": ["tenant"]
    }));

    assert!(result.is_err());
}

#[test]
fn permission_id_deserialization_rejects_excessive_length() {
    let permission_id = format!("resource:{}", "x".repeat(PermissionId::MAX_LENGTH));
    let result = serde_json::from_value::<PermissionId>(serde_json::json!(permission_id));

    assert!(result.is_err());
}

#[test]
fn permission_id_valid_round_trip_preserves_components() {
    let permission = RolePermission {
        permission_id: PermissionId::new("repo.v2:read").expect("valid permission id"),
        scopes: vec![Scope::Tenant],
    };

    let json = serde_json::to_value(&permission).expect("serialize permission");
    let decoded: RolePermission = serde_json::from_value(json).expect("deserialize permission");

    assert_eq!(decoded.permission_id.resource_type(), "repo.v2");
    assert_eq!(decoded.permission_id.name(), "read");
}

#[test]
fn validated_identifier_deserialization_rejects_values_bypassing_constructors() {
    let invalid_role = serde_json::from_str::<crate::RoleId>("\"\"").unwrap_err();
    assert!(invalid_role.to_string().contains("cannot be empty"));

    let invalid_resource = serde_json::from_str::<crate::ResourceTypeId>(r#""A-B""#).unwrap_err();
    assert!(
        invalid_resource
            .to_string()
            .contains("lowercase alphanumeric")
    );
}

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

#[test]
fn given_hardware_token_when_recent_auth_is_required_then_assurance_is_not_substituted() {
    assert!(!AcrLevel::HardwareToken.satisfies(AcrLevel::RecentAuth));
    assert!(AcrLevel::RecentAuth.satisfies(AcrLevel::RecentAuth));
}

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
fn jwt_context_collection_deserialization_is_bounded() {
    let oversized = serde_json::json!({
        "orgs": (0..=500).map(|index| serde_json::json!({"org_id": format!("org-{index}")})).collect::<Vec<_>>()
    });
    let error = serde_json::from_value::<JwtContext>(oversized)
        .expect_err("JWT organization claims must be bounded");
    assert!(error.to_string().contains("orgs exceeds maximum"));
}

#[test]
fn token_scope_deserialization_rejects_ambiguous_restrictions() {
    for payload in [
        serde_json::json!({"scope_strings": ["document:read"]}),
        serde_json::json!({
            "scope_type": "full_access",
            "scope_strings": ["document:read"]
        }),
    ] {
        let error = serde_json::from_value::<TokenScopeConfig>(payload)
            .expect_err("restricted token scope must have one unambiguous discriminator");
        assert!(
            error.to_string().contains("scope_type") || error.to_string().contains("full_access")
        );
    }
}

#[test]
fn token_scope_deserialization_preserves_explicit_full_access_default() {
    let decoded = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({}))
        .expect("an empty scope object retains the documented full-access default");
    assert_eq!(decoded.scope_type, crate::TokenScopeType::FullAccess);
}

#[test]
fn token_scope_deserialization_bounds_nested_collections() {
    let too_many_scope_strings = serde_json::json!({
        "scope_type": "scope_strings",
        "scope_strings": (0..=200).map(|index| format!("doc:{index}")).collect::<Vec<_>>()
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_scope_strings)
            .expect_err("scope strings must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );

    let too_many_selected_resources = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_selection": "selected",
            "selected_resources": (0..=1000).map(|index| format!("doc_{index}")).collect::<Vec<_>>()
        }
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_selected_resources)
            .expect_err("selected resources must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );

    let too_many_permission_values = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_permissions": {
                "document": (0..=500).map(|index| format!("doc:{index}")).collect::<Vec<_>>()
            }
        }
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_permission_values)
            .expect_err("permission values must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );
}

#[test]
fn evaluation_batch_deserialization_rejects_more_than_the_batch_limit() {
    let evaluations = (0..=crate::MAX_BATCH_EVALUATIONS)
        .map(|_| {
            serde_json::json!({
                "subject": { "type": "user", "id": "user_123" },
                "resource": { "type": "document", "id": "doc_123" },
                "action": { "name": "read" }
            })
        })
        .collect::<Vec<_>>();

    let payload = serde_json::json!({ "evaluations": evaluations });
    assert!(
        serde_json::from_value::<BatchEvaluationRequest>(payload.clone())
            .expect_err("evaluation batches must be bounded")
            .to_string()
            .contains("evaluations exceeds maximum")
    );
    assert!(
        serde_json::from_value::<ApiBatchEvaluationRequest>(payload)
            .expect_err("API evaluation batches must be bounded")
            .to_string()
            .contains("evaluations exceeds maximum")
    );
}
