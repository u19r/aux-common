use crate::{PermissionId, RolePermission, Scope};

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
