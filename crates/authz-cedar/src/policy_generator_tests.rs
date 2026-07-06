use std::collections::HashMap;

use authz_types::{
    AcrLevel, ConfigurationModel, PermissionActionRef, PermissionId, Scope, StepUpRule,
};
use cedar_policy::PolicySet;

use crate::generate_static_policies;

fn permission_actions(resource_type: &str, action_names: &[String]) -> Vec<PermissionActionRef> {
    action_names
        .iter()
        .map(|action_name| PermissionActionRef {
            resource_type: resource_type.into(),
            action_name: action_name.clone(),
        })
        .collect()
}

fn parse_policy_set(policies_json: &str) -> PolicySet {
    PolicySet::from_json_str(policies_json).expect("policy set json")
}

fn template_texts(policy_set: &PolicySet) -> Vec<String> {
    policy_set
        .templates()
        .map(|template| template.to_cedar())
        .collect()
}

fn linked_role_ids(policy_set: &PolicySet) -> Vec<String> {
    let mut role_ids = policy_set
        .policies()
        .filter(|policy| !policy.is_static())
        .map(|policy| {
            let links = policy.template_links().expect("template links");
            links
                .values()
                .next()
                .expect("principal slot binding")
                .to_string()
        })
        .collect::<Vec<_>>();
    role_ids.sort();
    role_ids
}

fn static_policy_texts(policy_set: &PolicySet) -> Vec<String> {
    policy_set
        .policies()
        .filter(|policy| policy.is_static())
        .map(|policy| policy.to_cedar().expect("static policy text"))
        .collect()
}

#[test]
fn policy_generation_emits_role_policies() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
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
        permissions: vec![authz_types::Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            description: None,
            actions: permission_actions("document", &["read".into(), "write".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![authz_types::Scope::Org],
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
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    let policy_text = template_texts(&policy_set).join("\n");
    assert_eq!(2, policy_set.num_of_templates(), "one template per action");
    assert_eq!(
        vec!["Authz::Role::\"editor\"", "Authz::Role::\"editor\""],
        linked_role_ids(&policy_set),
        "expected one linked policy per role/action"
    );
    assert!(policy_text.contains("document:read"));
    assert!(policy_text.contains("document:write"));
    assert!(
        policy_text.contains("allowed_actions") && policy_text.contains("document:read"),
        "token guard should be present"
    );
}

#[test]
fn org_owner_policy_is_scoped_to_org() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![
            authz_types::ResourceType {
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
            },
            authz_types::ResourceType {
                id: "organization".into(),
                name: "Organization".into(),
                description: None,
                actions: vec![authz_types::ActionDefinition {
                    name: "manage".into(),
                    description: None,
                }],
                context_schema: None,
            },
        ],
        permissions: vec![
            authz_types::Permission {
                id: "repo:admin".into(),
                name: "Repo Admin".into(),
                description: None,
                actions: permission_actions("repository", &["read".into(), "write".into()]),
                not_actions: vec![],
            },
            authz_types::Permission {
                id: "org:manage".into(),
                name: "Org Manage".into(),
                description: None,
                actions: permission_actions("organization", &["manage".into()]),
                not_actions: vec![],
            },
        ],
        roles: vec![authz_types::Role {
            id: "owner-role".into(),
            name: "org:owner".into(),
            description: None,
            permissions: vec![
                authz_types::RolePermission {
                    permission_id: PermissionId::new("repo:admin").expect("permission id"),
                    scopes: vec![authz_types::Scope::Org],
                },
                authz_types::RolePermission {
                    permission_id: PermissionId::new("org:manage").expect("permission id"),
                    scopes: vec![authz_types::Scope::Org],
                },
            ],
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
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    // Owner policies must include org scoping condition.
    let owner_policies: Vec<_> = template_texts(&policy_set)
        .into_iter()
        .filter(|p| p.contains("?principal"))
        .collect();
    assert!(
        !owner_policies.is_empty(),
        "expected owner policies to be generated"
    );
    for policy in owner_policies {
        assert!(
            policy.contains("resource has org_id")
                && policy.contains("principal has org_id")
                && policy.contains("resource.org_id")
                && policy.contains("principal.org_id"),
            "owner policies must be org-scoped: {policy}"
        );
    }
}

#[test]
fn step_up_policy_includes_session_guard() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("write".to_string(), "mfa".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "write".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            description: None,
            actions: permission_actions("document", &["write".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![authz_types::StepUpRule::require_acr(
            "mfa",
            "Require MFA",
            authz_types::AcrLevel::MultiFactor,
        )],
        step_up_config,
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    let policy_text = template_texts(&policy_set).join("\n");
    assert!(
        policy_text.contains("session_present"),
        "step-up guard should require session"
    );
    assert!(
        policy_text.contains("session_acr"),
        "step-up guard should require MFA ACR"
    );
}

#[test]
fn policy_generation_emits_scope_guards_for_all_scopes() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![
                    Scope::Tenant,
                    Scope::Org,
                    Scope::Group,
                    Scope::Own,
                    Scope::Shared,
                    Scope::Public,
                    Scope::OrgRelationship,
                    Scope::GroupRelationship,
                    Scope::resource("document"),
                ],
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
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    let policy_text = template_texts(&policy_set).join("\n");
    assert!(
        policy_text.contains("resource has org_id")
            && policy_text.contains("principal has org_id")
            && policy_text.contains("resource.org_id")
            && policy_text.contains("principal.org_id"),
        "org guard should be present"
    );
    assert!(
        policy_text.contains("resource.group_id") && policy_text.contains("principal.group_id"),
        "group guard should be present"
    );
    assert!(
        policy_text.contains("resource.owner_id") && policy_text.contains("principal.id"),
        "own guard should be present"
    );
    assert!(
        policy_text.contains("resource.shared_with") && policy_text.contains("principal.id"),
        "shared guard should be present"
    );
    assert!(
        policy_text.contains("resource.is_public"),
        "public guard should be present"
    );
    assert!(
        policy_text.contains("resource.org_parents") && policy_text.contains("contains(principal)"),
        "org relationship guard should be present"
    );
    assert!(
        policy_text.contains("resource.group_parents")
            && policy_text.contains("contains(principal)"),
        "group relationship guard should be present"
    );
    assert!(
        policy_text.contains("resource_scopes") && policy_text.contains("Authz::Role::\"reader\""),
        "resource scope should be role-specific"
    );
}

#[test]
fn step_up_policy_includes_auth_age_guard() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("recent".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    let policy_text = template_texts(&policy_set).join("\n");
    assert!(
        policy_text.contains("session_auth_age_present"),
        "auth age guard should require auth age"
    );
    assert!(
        policy_text.contains("session_auth_age_seconds"),
        "auth age guard should enforce max age"
    );
    assert!(
        policy_text.contains("token_present"),
        "auth age guard should allow api keys"
    );
}

#[test]
fn step_up_policy_includes_mfa_age_and_amr_guards() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("mfa".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule {
            rule_id: "mfa".into(),
            name: "Require MFA".into(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: Some(120),
            required_amr: vec!["webauthn".into(), "otp".into()],
            applies_to_api_keys: true,
        }],
        step_up_config,
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let policies_json = generate_static_policies(&config).expect("policies");
    let policy_set = parse_policy_set(&policies_json);
    let policy_text = template_texts(&policy_set).join("\n");
    assert!(
        policy_text.contains("session_mfa_age_present"),
        "mfa age guard should require mfa age"
    );
    assert!(
        policy_text.contains("session_mfa_age_seconds"),
        "mfa age guard should enforce max age"
    );
    assert!(
        policy_text.contains("session_amr") && policy_text.contains("webauthn"),
        "amr guard should include webauthn"
    );
    assert!(
        policy_text.contains("session_amr") && policy_text.contains("otp"),
        "amr guard should include otp"
    );
}

#[test]
fn matching_role_shapes_share_one_template_and_one_link_per_role() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![
            authz_types::Role {
                id: "reader-a".into(),
                name: "Reader A".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:reader").expect("permission id"),
                    scopes: vec![Scope::Org],
                }],
                actions: vec![],
                not_actions: vec![],
            },
            authz_types::Role {
                id: "reader-b".into(),
                name: "Reader B".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:reader").expect("permission id"),
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

    let policy_set = parse_policy_set(&generate_static_policies(&config).expect("policies"));
    assert_eq!(
        1,
        policy_set.num_of_templates(),
        "shared shape should collapse"
    );
    assert_eq!(
        2,
        policy_set
            .policies()
            .filter(|policy| !policy.is_static())
            .count(),
        "expected one linked policy per role"
    );
    assert_eq!(
        vec!["Authz::Role::\"reader-a\"", "Authz::Role::\"reader-b\""],
        linked_role_ids(&policy_set)
    );
}

#[test]
fn public_read_remains_static_and_is_not_linked() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
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

    let policy_set = parse_policy_set(&generate_static_policies(&config).expect("policies"));
    let static_policies = static_policy_texts(&policy_set);
    assert_eq!(1, static_policies.len(), "public read should stay static");
    assert!(
        static_policies[0].contains("resource.is_public"),
        "public read guard should stay on a static policy"
    );
}

#[test]
fn different_scope_guards_produce_distinct_templates() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            name: "Reader".into(),
            description: None,
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant, Scope::Org],
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

    let policy_set = parse_policy_set(&generate_static_policies(&config).expect("policies"));
    assert_eq!(2, policy_set.num_of_templates(), "tenant and org differ");
}

#[test]
fn different_step_up_guards_produce_distinct_templates() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("write".to_string(), "mfa".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
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
        permissions: vec![authz_types::Permission {
            id: "document:editor".into(),
            name: "Editor".into(),
            description: None,
            actions: permission_actions("document", &["read".into(), "write".into()]),
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![authz_types::StepUpRule::require_acr(
            "mfa",
            "Require MFA",
            authz_types::AcrLevel::MultiFactor,
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let policy_set = parse_policy_set(&generate_static_policies(&config).expect("policies"));
    assert_eq!(
        2,
        policy_set.num_of_templates(),
        "read and write differ on step-up"
    );
}

#[test]
fn different_effects_produce_distinct_templates() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![authz_types::Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![],
            actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
            }],
            not_actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
            }],
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

    let policy_set = parse_policy_set(&generate_static_policies(&config).expect("policies"));
    assert_eq!(
        2,
        policy_set.num_of_templates(),
        "permit and forbid must stay distinct"
    );
}
