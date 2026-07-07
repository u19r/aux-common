use std::collections::HashMap;

use authz_types::{
    ActionDefinition, ConfigurationModel, Permission, PermissionActionRef, PermissionId,
    ResourceType, Role, RolePermission, Scope,
};
use cedar_policy::PolicySet;

use crate::{SLICE_SOFT_MAX_BYTES, compile_policy_bundle};

fn base_resource() -> ResourceType {
    ResourceType {
        id: "document".into(),
        name: "Document".into(),
        description: None,
        actions: vec![
            ActionDefinition {
                name: "read".into(),
                description: None,
            },
            ActionDefinition {
                name: "write".into(),
                description: None,
            },
        ],
        context_schema: None,
    }
}

fn permission_actions(resource_type: &str, action_names: &[&str]) -> Vec<PermissionActionRef> {
    action_names
        .iter()
        .map(|action_name| PermissionActionRef {
            resource_type: resource_type.into(),
            action_name: (*action_name).into(),
        })
        .collect()
}

fn parse_policy_set(payload: &str) -> PolicySet {
    PolicySet::from_json_str(payload).expect("policy set json")
}

fn legacy_policy_payload_len(roles: &[Role]) -> usize {
    let token_guard = |action_id: &str| {
        format!(
            "(!context._authz.token_present || (context._authz.token_valid && \
             (!context._authz.token_resource_filter_enabled || resource in \
             context._authz.token_resource_filter) && (!context._authz.token_org_id_present || \
             (resource has org_id && resource.org_id == context._authz.token_org_id && \
             context._authz.token_owner_org_ids.contains(context._authz.token_org_id))) && \
             context._authz.allowed_actions.contains(\"{action_id}\")))"
        )
    };

    let mut policies = Vec::new();
    let mut idx = 0_usize;
    for role in roles {
        for action_name in ["read", "write"] {
            policies.push(format!(
                r#"@id("pol_{idx}")
permit(
  principal in Authz::Role::"{role_id}",
  action == Authz::Action::"document:{action_name}",
  resource is Authz::Document
) when {{ {guard} }};"#,
                role_id = role.id,
                guard = token_guard(&format!("document:{action_name}"))
            ));
            idx += 1;
        }
    }
    policies.push(format!(
        r#"@id("pol_{idx}")
permit(
  principal,
  action == Authz::Action::"document:read",
  resource is Authz::Document
) when {{ resource.is_public == true && {} }};"#,
        token_guard("document:read")
    ));

    serde_json::to_string(&policies)
        .expect("legacy policy payload")
        .len()
}

#[test]
fn manifest_includes_slices() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![base_resource()],
        permissions: vec![Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            actions: permission_actions("document", &["read", "write"]),
            not_actions: vec![],
            description: None,
        }],
        roles: vec![Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
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
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    assert_eq!(1, bundle.schema_slices.len());
    assert_eq!(1, bundle.policy_slices.len());
    assert!(bundle.base_schema_json.len() > 10);
    assert_eq!(1, bundle.manifest.policy_slices.len());
    assert_eq!("document", bundle.manifest.policy_slices[0].key);
}

#[test]
fn policy_slice_chunks_when_soft_limit_is_exceeded() {
    // Build enough roles to force chunking for a single resource type.
    let action_names = (0..128).map(|idx| format!("a{idx}")).collect::<Vec<_>>();
    let mut roles = Vec::new();
    let role_suffix = "x".repeat(118);
    for idx in 0..200 {
        roles.push(Role {
            id: format!("role_{idx}_{role_suffix}"),
            name: format!("Bulk {idx}"),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        });
    }

    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: action_names
                .iter()
                .map(|name| ActionDefinition {
                    name: name.clone(),
                    description: None,
                })
                .collect(),
            context_schema: None,
        }],
        permissions: vec![Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            actions: action_names
                .iter()
                .map(|action_name| PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: action_name.clone(),
                })
                .collect(),
            not_actions: vec![],
            description: None,
        }],
        roles,
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    assert!(
        bundle.policy_slices.len() > 1,
        "expected multiple policy slices for oversized resource policy set"
    );
    assert!(
        bundle
            .policy_slices
            .iter()
            .all(|slice| slice.size_bytes <= SLICE_SOFT_MAX_BYTES)
    );
    for slice in &bundle.policy_slices {
        let policy_set = parse_policy_set(&slice.policies_json);
        for linked in policy_set.policies().filter(|policy| !policy.is_static()) {
            let template_id = linked.template_id().expect("template id");
            assert!(
                policy_set.template(template_id).is_some(),
                "slice must include linked policy template"
            );
        }
    }
}

#[test]
fn compact_policy_slices_are_smaller_than_legacy_duplicate_payload() {
    let mut roles = Vec::new();
    for idx in 0..200 {
        roles.push(Role {
            id: format!("role_{idx}"),
            name: format!("Bulk {idx}"),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        });
    }

    let legacy_bytes = legacy_policy_payload_len(&roles);
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![base_resource()],
        permissions: vec![Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            actions: permission_actions("document", &["read", "write"]),
            not_actions: vec![],
            description: None,
        }],
        roles,
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let compact_bytes: usize = bundle
        .policy_slices
        .iter()
        .map(|slice| slice.size_bytes)
        .sum();
    assert!(
        compact_bytes < legacy_bytes,
        "expected compact payload to beat duplicated legacy payload, compact={compact_bytes}, \
         legacy={legacy_bytes}"
    );
}

#[test]
fn bundle_compilation_is_deterministic() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![base_resource()],
        permissions: vec![Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            actions: permission_actions("document", &["read", "write"]),
            not_actions: vec![],
            description: None,
        }],
        roles: vec![
            Role {
                id: "role_a".into(),
                name: "Role A".into(),
                description: None,
                permissions: vec![RolePermission {
                    permission_id: PermissionId::new("document:editor").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                }],
                actions: vec![],
                not_actions: vec![],
            },
            Role {
                id: "role_b".into(),
                name: "Role B".into(),
                description: None,
                permissions: vec![RolePermission {
                    permission_id: PermissionId::new("document:editor").expect("permission id"),
                    scopes: vec![Scope::Org],
                }],
                actions: vec![],
                not_actions: vec![],
            },
        ],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle_a = compile_policy_bundle(&config, 1).expect("bundle a");
    let bundle_b = compile_policy_bundle(&config, 1).expect("bundle b");
    assert_eq!(bundle_a.policy_slices, bundle_b.policy_slices);
}

#[test]
fn compiled_bundle_round_trips_through_public_json() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![base_resource()],
        permissions: vec![Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            actions: permission_actions("document", &["read", "write"]),
            not_actions: vec![],
            description: None,
        }],
        roles: vec![Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
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
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 42).expect("bundle");
    let json = bundle.as_json().expect("bundle json");
    let decoded: crate::CompiledBundle = serde_json::from_str(&json).expect("decoded bundle");

    assert_eq!(decoded, bundle);
    assert_eq!(decoded.version, 42);
}
