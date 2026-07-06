use std::collections::HashMap;

use authz_types::{
    ConfigurationModel, Permission, PermissionActionRef, PermissionId, ResourceType, Role,
    RolePermission,
};
use cedar_policy::PolicySet;

use crate::generate_static_policies;

#[test]
fn relationship_scope_policies_present() {
    let permission_actions = vec![
        PermissionActionRef {
            resource_type: "repository".into(),
            action_name: "read".into(),
        },
        PermissionActionRef {
            resource_type: "repository".into(),
            action_name: "write".into(),
        },
    ];
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "repository".into(),
            name: "Repository".into(),
            description: None,
            actions: vec![
                authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                authz_types::ActionDefinition {
                    name: "write".into(),
                    description: None,
                },
            ],
            context_schema: None,
        }],
        permissions: vec![Permission {
            id: "repo:contrib".into(),
            name: "Contributor".into(),
            description: None,
            actions: permission_actions,
            not_actions: vec![],
        }],
        roles: vec![Role {
            id: "contributor".into(),
            name: "Contributor".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("repo:contrib").expect("permission id"),
                scopes: vec![authz_types::Scope::OrgRelationship],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let policy_set = PolicySet::from_json_str(generate_static_policies(&config).expect("policies"))
        .expect("policy set");
    let policy_text = policy_set
        .templates()
        .map(|template| template.to_cedar())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        policy_text.contains("resource.org_parents") && policy_text.contains("contains(principal)"),
        "org relationship scope condition rendered"
    );
}
