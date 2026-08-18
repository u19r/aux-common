use std::{collections::HashMap, str::FromStr};

use authz_types::{
    ActionDefinition, ConfigurationModel, Permission, PermissionActionRef, PermissionId,
    ResourceType, Role, RolePermission, Scope,
};
use cedar_policy::{EntityUid, Policy, PolicyId, PolicySet, SlotId, Template};

use crate::{
    MAX_SCHEMA_SLICES, SLICE_SOFT_MAX_BYTES, SchemaSlice, compile_policy_bundle, parse_policy_sets,
    validate_bundle_integrity,
};

#[test]
fn validation_given_unknown_action_then_rejects_policy_set() {
    use std::str::FromStr;

    use cedar_policy::PolicySet;

    let config = basic_config();
    let schema = crate::generate_schema_for_resource(&config, "document").expect("schema");
    let policies = PolicySet::from_str(
        r#"permit(principal, action == Authz::Action::"document:unknown", resource);"#,
    )
    .expect("syntactically valid policy");

    let result = crate::validation::validate_policy_set(&schema, &policies, 0);

    assert!(
        result.is_err(),
        "unknown action must fail strict validation"
    );
}

fn validate_policy_text(
    config: &authz_types::ValidatedConfigurationModel,
    policy: &str,
) -> Result<(), crate::CedarError> {
    use std::str::FromStr;

    let schema = crate::generate_schema_for_resource(config, "document").expect("schema");
    let policies = PolicySet::from_str(policy).expect("syntactically valid policy");
    crate::validation::validate_policy_set(
        &schema,
        &policies,
        crate::validation::GENERATED_POLICY_MAX_DEREF_LEVEL,
    )
}

#[test]
fn validation_given_action_resource_type_mismatch_then_rejects_policy_set() {
    let result = validate_policy_text(
        &basic_config(),
        r#"permit(principal, action == Authz::Action::"document:read", resource is Authz::Org);"#,
    );
    assert!(result.is_err());
}

#[test]
fn validation_given_optional_attribute_without_has_then_rejects_policy_set() {
    let result = validate_policy_text(
        &basic_config(),
        r#"permit(principal, action == Authz::Action::"document:read", resource) when { resource.org_id == "org_acme" };"#,
    );
    assert!(result.is_err());
}

#[test]
fn validation_given_incorrect_comparison_type_then_rejects_policy_set() {
    let result = validate_policy_text(
        &basic_config(),
        r#"permit(principal, action == Authz::Action::"document:read", resource) when { resource.is_public == "true" };"#,
    );
    assert!(result.is_err());
}

#[test]
fn validation_given_policy_from_another_schema_slice_then_rejects_policy_set() {
    let result = validate_policy_text(
        &basic_config(),
        r#"permit(principal, action == Authz::Action::"issue:read", resource is Authz::Issue);"#,
    );
    assert!(result.is_err());
}

#[test]
fn validation_given_template_link_bound_to_incompatible_principal_then_rejects_policy_set() {
    use std::str::FromStr;

    use cedar_policy::{EntityUid, PolicyId, SlotId, Template};

    let config = basic_config();
    let schema = crate::generate_schema_for_resource(&config, "document").expect("schema");
    let template = Template::parse(
        Some(PolicyId::new("template_read")),
        r#"permit(principal in ?principal, action == Authz::Action::"document:read", resource);"#,
    )
    .expect("template");
    let mut policies = PolicySet::new();
    policies.add_template(template).expect("add template");
    policies
        .link(
            PolicyId::new("template_read"),
            PolicyId::new("linked_read"),
            HashMap::from([(
                SlotId::principal(),
                EntityUid::from_str(r#"Authz::Document::"doc1""#).expect("uid"),
            )]),
        )
        .expect("link is syntactically complete");

    let result = crate::validation::validate_policy_set(
        &schema,
        &policies,
        crate::validation::GENERATED_POLICY_MAX_DEREF_LEVEL,
    );

    assert!(result.is_err());
}

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

fn basic_config() -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![base_resource()],
        permissions: vec![],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("valid basic config")
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

#[test]
fn native_policy_set_rejects_policy_template_and_link_id_collisions() {
    let mut policies = PolicySet::new();
    let policy = Policy::parse(
        Some(PolicyId::new("shared_id")),
        r#"permit(principal, action, resource);"#,
    )
    .expect("static policy");
    policies.add(policy.clone()).expect("first policy");
    assert!(
        policies.add(policy).is_err(),
        "duplicate policy id must fail"
    );

    let colliding_template = Template::parse(
        Some(PolicyId::new("shared_id")),
        r#"permit(principal in ?principal, action, resource);"#,
    )
    .expect("template");
    assert!(
        policies.add_template(colliding_template).is_err(),
        "template id must not collide with a policy id"
    );

    let template = Template::parse(
        Some(PolicyId::new("template_id")),
        r#"permit(principal in ?principal, action, resource);"#,
    )
    .expect("template");
    policies.add_template(template).expect("unique template");
    let values = HashMap::from([(
        SlotId::principal(),
        EntityUid::from_str(r#"Authz::Role::"reader""#).expect("role uid"),
    )]);
    policies
        .link(
            PolicyId::new("template_id"),
            PolicyId::new("linked_id"),
            values.clone(),
        )
        .expect("first link");
    assert!(
        policies
            .link(
                PolicyId::new("template_id"),
                PolicyId::new("linked_id"),
                values,
            )
            .is_err(),
        "linked policy id collision must fail"
    );
}

#[test]
fn native_policy_set_rejects_incomplete_slot_binding() {
    let template = Template::parse(
        Some(PolicyId::new("template_id")),
        r#"permit(principal in ?principal, action, resource);"#,
    )
    .expect("template");
    let mut policies = PolicySet::new();
    policies.add_template(template).expect("template");

    assert!(
        policies
            .link(
                PolicyId::new("template_id"),
                PolicyId::new("linked_id"),
                HashMap::new(),
            )
            .is_err(),
        "missing principal slot must fail"
    );
}

#[test]
fn generated_policy_set_losslessly_round_trips_through_pst_json_and_cedar_text() {
    let bundle = compile_policy_bundle(&basic_config(), 1).expect("bundle");
    let original = PolicySet::from_json_str(&bundle.policy_slices[0].policies_json)
        .expect("generated policy JSON");
    let original_policy_count = original.num_of_policies();
    let original_template_count = original.num_of_templates();
    let pst = original.to_pst().expect("generated PST");
    let from_pst = PolicySet::from_pst(pst.clone()).expect("PST policy set");
    assert_eq!(from_pst.to_pst().expect("round-trip PST"), pst);

    let json = from_pst.clone().to_json().expect("PST JSON");
    let from_json = PolicySet::from_json_value(json).expect("parsed PST JSON");
    assert_eq!(from_json.num_of_policies(), original_policy_count);
    assert_eq!(from_json.num_of_templates(), original_template_count);

    let cedar_text = from_json.to_string();
    let from_text = PolicySet::from_str(&cedar_text).expect("diagnostic Cedar text");
    assert_eq!(from_text.num_of_policies(), original_policy_count);
}

#[test]
fn parsed_bundles_reject_oversized_policy_slices_before_cedar_parsing() {
    let mut bundle = compile_policy_bundle(&basic_config(), 1).expect("bundle");
    bundle.policy_slices[0].policies_json = "x".repeat(SLICE_SOFT_MAX_BYTES + 1);

    let error = parse_policy_sets(&bundle).expect_err("oversized policy slices must be bounded");
    assert!(error.to_string().contains("policy slice exceeds maximum"));
}

#[test]
fn parsed_bundles_reject_excessive_schema_counts_before_hashing() {
    let config = basic_config();
    let mut bundle = compile_policy_bundle(&config, 1).expect("bundle");
    bundle.schema_slices = vec![
        SchemaSlice {
            resource_type: "document".into(),
            schema_json: String::new(),
            size_bytes: 0,
        };
        MAX_SCHEMA_SLICES + 1
    ];

    let error = validate_bundle_integrity(&bundle)
        .expect_err("bundles with excessive schema counts must be rejected");
    assert!(
        error
            .to_string()
            .contains("schema slice count exceeds maximum")
    );
}

#[test]
fn compiled_bundle_manifest_binds_all_payloads_with_digests() {
    let bundle = compile_policy_bundle(&basic_config(), 7).expect("bundle");

    assert_eq!(bundle.manifest.version, 7);
    assert!(
        bundle
            .manifest
            .config_fingerprint
            .as_deref()
            .is_some_and(|value| value.len() == 64)
    );
    assert!(bundle.manifest.base_schema_sha256.is_some());
    assert!(
        bundle
            .manifest
            .schema_slices
            .iter()
            .all(|slice| slice.sha256.is_some())
    );
    assert!(
        bundle
            .manifest
            .policy_slices
            .iter()
            .all(|slice| slice.sha256.is_some())
    );
    parse_policy_sets(&bundle).expect("compiled bundle integrity");
}

#[test]
fn parsed_bundle_rejects_missing_or_mutated_integrity_metadata() {
    let original = compile_policy_bundle(&basic_config(), 1).expect("bundle");

    let mut missing_fingerprint = original.clone();
    missing_fingerprint.manifest.config_fingerprint = None;
    let error = parse_policy_sets(&missing_fingerprint).expect_err("legacy metadata must reject");
    assert!(
        error
            .to_string()
            .contains("configuration fingerprint is missing")
    );

    let mut mutated_payload = original.clone();
    mutated_payload.policy_slices[0].policies_json.push(' ');
    let error = parse_policy_sets(&mutated_payload).expect_err("mutated payload must reject");
    assert!(
        error
            .to_string()
            .contains("policy slice size metadata mismatch")
    );

    let mut mutated_manifest = original;
    mutated_manifest.manifest.base_schema_sha256 = Some("0".repeat(64));
    let error = parse_policy_sets(&mutated_manifest).expect_err("mutated manifest must reject");
    assert!(error.to_string().contains("base schema digest mismatch"));
}
