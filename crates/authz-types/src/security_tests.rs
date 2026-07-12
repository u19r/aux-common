use crate::{JwtContext, PermissionId, RolePermission, Scope, SessionContext};

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
fn jwt_context_completeness_is_derived_fail_closed() {
    let context = JwtContext {
        roles_complete: false,
        claims_complete: true,
        ..JwtContext::default()
    };

    assert!(!context.is_complete());
}
