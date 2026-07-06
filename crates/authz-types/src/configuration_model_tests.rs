use std::collections::HashMap;

use crate::{
    AcrLevel, AuthnProviderConfig, ConfigurationModel, MAX_ACTIONS_PER_RESOURCE_TYPE,
    MAX_PERMISSIONS, MAX_ROLES, Permission, PermissionActionRef, PermissionId, ResourceType, Role,
    RoleActionRef, RolePermission, Scope, ScopeMappingEntry, StepUpConfig, StepUpRule,
    ValidationError,
};

#[test]
fn detects_duplicate_step_up_rule_ids() {
    let model = ConfigurationModel {
        version: 1,
        resource_types: Vec::new(),
        permissions: Vec::new(),
        roles: Vec::new(),
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: vec![
            StepUpRule::require_acr("r1", "one", AcrLevel::MultiFactor),
            StepUpRule::require_acr("r1", "dup", AcrLevel::HardwareToken),
        ],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    };
    let errs = model.validate().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ValidationError::DuplicateId(id) if id == "r1"))
    );
}

#[test]
fn missing_step_up_rule_reference_fails() {
    let mut action_rules = HashMap::new();
    action_rules.insert("write".into(), "missing-rule".into());
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "doc".into(),
        StepUpConfig {
            default_rule: None,
            action_rules,
        },
    );
    let model = ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "doc".into(),
            name: "doc".into(),
            description: None,
            actions: Vec::new(),
            context_schema: None,
        }],
        permissions: Vec::new(),
        roles: Vec::new(),
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config,
        default_step_up_rule: None,
        description: None,
    };
    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::ReferenceNotFound { entity_type, id }
                if entity_type == &"step_up_rule".to_string() && id == "missing-rule"
        )
    }));
}

#[test]
fn duplicate_resource_type_names_are_rejected_case_insensitively() {
    let mut model = base_model();
    model.resource_types.push(ResourceType {
        id: "repo_alt".into(),
        name: "REPO".into(),
        description: None,
        actions: vec![crate::ActionDefinition {
            name: "read".into(),
            description: None,
        }],
        context_schema: None,
    });

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(e, ValidationError::DuplicateId(id) if id == "resource_type_name:repo")
    }));
}

#[test]
fn duplicate_permission_names_are_rejected_case_insensitively() {
    let mut model = base_model();
    model.permissions.push(Permission {
        id: "repo:read_alt".into(),
        name: "REPO_READ".into(),
        description: None,
        actions: vec![PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "read".into(),
        }],
        not_actions: vec![],
    });

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(e, ValidationError::DuplicateId(id) if id == "permission_name:repo_read")
    }));
}

#[test]
fn duplicate_role_names_are_rejected_case_insensitively() {
    let mut model = base_model();
    model.roles.push(Role {
        id: "repo_auditor".into(),
        name: "REPO_VIEWER".into(),
        description: None,
        permissions: vec![RolePermission {
            permission_id: PermissionId::new("repo:read".to_string()).expect("permission id"),
            scopes: vec![Scope::Tenant],
        }],
        actions: vec![],
        not_actions: vec![],
    });

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(e, ValidationError::DuplicateId(id) if id == "role_name:repo_viewer")
    }));
}

#[test]
fn duplicate_resource_action_names_are_rejected_case_insensitively() {
    let mut model = base_model();
    model.resource_types[0]
        .actions
        .push(crate::ActionDefinition {
            name: "READ".into(),
            description: None,
        });

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::DuplicateId(id) if id == "resource_type_action_name:repo:read"
        )
    }));
}

#[test]
fn duplicate_entity_ids_are_rejected() {
    let mut model = base_model();
    model.resource_types.push(ResourceType {
        id: "repo".into(),
        name: "repo_2".into(),
        description: None,
        actions: vec![crate::ActionDefinition {
            name: "write".into(),
            description: None,
        }],
        context_schema: None,
    });
    model.permissions.push(Permission {
        id: "repo:read".into(),
        name: "repo_read_2".into(),
        description: None,
        actions: vec![PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "read".into(),
        }],
        not_actions: vec![],
    });
    model.roles.push(Role {
        id: "repo_viewer".into(),
        name: "repo_viewer_2".into(),
        description: None,
        permissions: vec![RolePermission {
            permission_id: PermissionId::new("repo:read".to_string()).expect("permission id"),
            scopes: vec![Scope::Tenant],
        }],
        actions: vec![],
        not_actions: vec![],
    });

    let errs = model.validate().unwrap_err();
    assert!(
        errs.iter().any(
            |e| matches!(e, ValidationError::DuplicateId(id) if id == "resource_type_id:repo")
        )
    );
    assert!(
        errs.iter().any(
            |e| matches!(e, ValidationError::DuplicateId(id) if id == "permission_id:repo:read")
        )
    );
    assert!(
        errs.iter()
            .any(|e| matches!(e, ValidationError::DuplicateId(id) if id == "role_id:repo_viewer"))
    );
}

#[test]
fn permissions_limit_exceeded_is_reported() {
    let mut model = base_model();
    model.permissions = (0..=MAX_PERMISSIONS)
        .map(|idx| Permission {
            id: format!("repo:perm_{idx}"),
            name: format!("repo_perm_{idx}"),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "repo".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        })
        .collect();

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::LimitExceeded {
                resource,
                limit,
                actual
            } if *resource == "permissions" && *limit == MAX_PERMISSIONS && *actual == MAX_PERMISSIONS + 1
        )
    }));
}

#[test]
fn roles_limit_exceeded_is_reported() {
    let mut model = base_model();
    model.roles = (0..=MAX_ROLES)
        .map(|idx| Role {
            id: format!("repo_role_{idx}"),
            name: format!("repo_role_{idx}"),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("repo:read".to_string()).expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        })
        .collect();

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::LimitExceeded {
                resource,
                limit,
                actual
            } if *resource == "roles" && *limit == MAX_ROLES && *actual == MAX_ROLES + 1
        )
    }));
}

#[test]
fn resource_type_actions_limit_exceeded_is_reported() {
    let mut model = base_model();
    model.resource_types[0].actions = (0..=MAX_ACTIONS_PER_RESOURCE_TYPE)
        .map(|idx| crate::ActionDefinition {
            name: format!("action_{idx}"),
            description: None,
        })
        .collect();

    let errs = model.validate().unwrap_err();
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::LimitExceeded {
                resource,
                limit,
                actual
            } if *resource == "resource_type_actions"
                && *limit == MAX_ACTIONS_PER_RESOURCE_TYPE
                && *actual == MAX_ACTIONS_PER_RESOURCE_TYPE + 1
        )
    }));
}

#[test]
fn wildcard_patterns_in_permission_and_role_actions_are_valid() {
    let mut model = base_model();
    model.resource_types[0]
        .actions
        .push(crate::ActionDefinition {
            name: "write".into(),
            description: None,
        });
    model.permissions[0].actions = vec![PermissionActionRef {
        resource_type: "re*".into(),
        action_name: "*ad".into(),
    }];
    model.roles[0].actions = vec![RoleActionRef {
        resource_type: "repo".into(),
        action_name: "wri*".into(),
        scopes: vec![Scope::Tenant],
    }];

    assert!(model.validate().is_ok());
}

#[test]
fn infix_wildcard_pattern_is_rejected() {
    let mut model = base_model();
    model.permissions[0].actions = vec![PermissionActionRef {
        resource_type: "re*po".into(),
        action_name: "read".into(),
    }];

    let errs = model.validate().expect_err("infix wildcard should fail");
    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "permissions[].actions[]" && message.contains("wildcard must be one of exact")
        )
    }));
}

#[test]
fn zero_match_wildcard_pattern_is_rejected() {
    let mut model = base_model();
    model.permissions[0].actions = vec![PermissionActionRef {
        resource_type: "repo".into(),
        action_name: "admin*".into(),
    }];

    let errs = model
        .validate()
        .expect_err("zero-match wildcard should fail");
    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "permissions[].actions[]"
                    && message.contains("wildcard pattern matched zero")
        )
    }));
}

#[test]
fn into_validated_expands_wildcard_action_references() {
    let mut model = base_model();
    model.resource_types[0]
        .actions
        .push(crate::ActionDefinition {
            name: "write".into(),
            description: None,
        });
    model.permissions[0].actions = vec![
        PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "read".into(),
        },
        PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "wri*".into(),
        },
        PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "*".into(),
        },
    ];

    let validated = model.into_validated().expect("config should validate");
    let permission = validated
        .permissions
        .iter()
        .find(|entry| entry.id == "repo:read")
        .expect("permission should exist");

    assert_eq!(permission.actions.len(), 2);
    assert_eq!(permission.actions[0].action_name, "read");
    assert_eq!(permission.actions[1].action_name, "write");
}

#[test]
fn scope_mapping_requires_permissions_or_child_scopes() {
    let mut model = base_model();
    model.scope_mappings.push(ScopeMappingEntry {
        scope: "repo:read".into(),
        permissions: Vec::new(),
        includes: Vec::new(),
    });

    let errs = model
        .validate()
        .expect_err("empty scope mapping should fail validation");

    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "scope_mappings[].permissions"
                    && message.contains("must include permissions or child scopes")
        )
    }));
}

#[test]
fn scope_mapping_rejects_unknown_permission_and_child_scope_references() {
    let mut model = base_model();
    model.scope_mappings = vec![
        ScopeMappingEntry {
            scope: "repo:read".into(),
            permissions: vec!["repo:read".into(), "repo:write".into()],
            includes: vec!["repo:admin".into()],
        },
        ScopeMappingEntry {
            scope: "repo:list".into(),
            permissions: vec!["repo:read".into()],
            includes: Vec::new(),
        },
    ];

    let errs = model
        .validate()
        .expect_err("unknown scope mapping references should fail");

    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::ReferenceNotFound { entity_type, id }
                if *entity_type == "permission" && id == "repo:write"
        )
    }));
    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::ReferenceNotFound { entity_type, id }
                if *entity_type == "scope_mapping" && id == "repo:admin"
        )
    }));
}

#[test]
fn authn_providers_must_use_https_and_supported_algorithms() {
    let mut model = base_model();
    model.authn_providers.push(AuthnProviderConfig {
        issuer: "http://issuer.example.test".into(),
        jwks_uri: "https://issuer.example.test/jwks.json".into(),
        algorithms: Some(vec!["PS256".into()]),
        audiences: Some(Vec::new()),
        subject_claim: "sub".into(),
        org_claim: None,
        cache_ttl_seconds: 300,
    });

    let errs = model
        .validate()
        .expect_err("invalid authn provider should fail validation");

    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "authn_providers[].issuer" && message == "issuer must be https"
        )
    }));
    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "authn_providers[].audiences"
                    && message == "audiences cannot be empty"
        )
    }));
    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "authn_providers[].algorithms"
                    && message.contains("unsupported alg PS256")
        )
    }));
}

#[test]
fn default_step_up_rule_must_reference_existing_rule() {
    let mut model = base_model();
    model.default_step_up_rule = Some("rule_missing".into());

    let errs = model
        .validate()
        .expect_err("missing default step-up rule should fail");

    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::ReferenceNotFound { entity_type, id }
                if *entity_type == "step_up_rule" && id == "rule_missing"
        )
    }));
}

#[test]
fn step_up_action_rule_must_reference_resource_action() {
    let mut model = base_model();
    model.step_up_rules = vec![StepUpRule::require_acr(
        "rule_mfa",
        "MFA",
        AcrLevel::MultiFactor,
    )];
    model.step_up_config.insert(
        "repo".into(),
        StepUpConfig {
            default_rule: None,
            action_rules: [("delete".to_string(), "rule_mfa".to_string())]
                .into_iter()
                .collect(),
        },
    );

    let errs = model
        .validate()
        .expect_err("unknown step-up action should fail");

    assert!(errs.iter().any(|error| {
        matches!(
            error,
            ValidationError::ReferenceNotFound { entity_type, id }
                if *entity_type == "resource_type_action" && id == "repo:delete"
        )
    }));
}

fn base_model() -> ConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "repo".into(),
            name: "repo".into(),
            description: None,
            actions: vec![crate::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![Permission {
            id: "repo:read".into(),
            name: "repo_read".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "repo".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![Role {
            id: "repo_viewer".into(),
            name: "repo_viewer".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("repo:read".to_string()).expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![RoleActionRef {
                resource_type: "repo".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
            }],
            not_actions: vec![],
        }],
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
}
