use serde_json::{Value, json};

use crate::{CreatePermissionRequest, CreateRoleRequest, RoleByNameInput, Scope};

#[test]
fn create_permission_request_rejects_null_description() {
    let payload = json!({
        "permission": {
            "name": "repo_read",
            "description": null,
            "actions": [
                {
                    "resource_type": "repository",
                    "action_name": "read"
                }
            ]
        }
    });

    let result = serde_json::from_value::<CreatePermissionRequest>(payload);
    assert!(result.is_err(), "description: null must be rejected");
}

#[test]
fn create_role_request_rejects_null_description() {
    let payload = json!({
        "role": {
            "name": "repo_viewer",
            "description": null,
            "permissions": [
                {
                    "permission_name": "repo_read",
                    "scopes": ["tenant"]
                }
            ]
        }
    });

    let result = serde_json::from_value::<CreateRoleRequest>(payload);
    assert!(result.is_err(), "description: null must be rejected");
}

#[test]
fn create_permission_request_omits_empty_not_actions_when_serialized() {
    let payload = json!({
        "permission": {
            "name": "repo_read",
            "actions": [
                {
                    "resource_type": "repository",
                    "action_name": "read"
                }
            ]
        }
    });
    let request: CreatePermissionRequest = serde_json::from_value(payload).expect("request");

    let encoded = serde_json::to_value(&request).expect("serialize");
    let permission = encoded.get("permission").expect("permission");
    assert!(
        permission.get("not_actions").is_none(),
        "empty not_actions must be omitted"
    );
}

#[test]
fn create_role_request_omits_empty_actions_and_not_actions_when_serialized() {
    let request = CreateRoleRequest {
        role: RoleByNameInput {
            name: "repo_viewer".to_string(),
            description: None,
            permissions: vec![crate::RolePermissionByNameInput {
                permission_name: "repo_read".to_string(),
                scopes: vec![Scope::Tenant],
            }],
            actions: Vec::new(),
            not_actions: Vec::new(),
        },
        description: None,
    };

    let encoded = serde_json::to_value(&request).expect("serialize");
    let role = encoded.get("role").expect("role");
    assert!(
        role.get("actions").is_none(),
        "empty actions must be omitted"
    );
    assert!(
        role.get("not_actions").is_none(),
        "empty not_actions must be omitted"
    );
    assert!(
        role.get("description").is_none(),
        "missing description should stay omitted"
    );
}

#[test]
fn create_role_request_accepts_omitted_actions() {
    let payload = json!({
        "role": {
            "name": "repo_viewer",
            "permissions": [
                {
                    "permission_name": "repo_read",
                    "scopes": ["tenant"]
                }
            ]
        }
    });

    let request: CreateRoleRequest = serde_json::from_value(payload).expect("request");
    let encoded = serde_json::to_value(&request).expect("serialize");
    let role: &Value = encoded.get("role").expect("role");
    assert!(role.get("actions").is_none(), "actions should stay omitted");
    assert!(
        role.get("not_actions").is_none(),
        "not_actions should stay omitted"
    );
}
