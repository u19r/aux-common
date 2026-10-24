use std::collections::HashMap;

use crate::{
    AccessAssignmentDurationSeconds, AccessAssignmentMode, AccessAssignmentPolicySpec, AcrLevel,
    AuthnProviderConfig, ConfigurationModel, MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS,
    MAX_ACTIONS_PER_RESOURCE_TYPE, MAX_AUTHN_PROVIDERS, MAX_PERMISSION_ACTION_REFS,
    MAX_PERMISSIONS, MAX_RESOURCE_TYPES, MAX_ROLE_ACTION_REFS, MAX_ROLE_ENTRY_SCOPES,
    MAX_ROLE_PERMISSION_REFS, MAX_ROLES, MAX_SCOPE_MAPPING_INCLUDES, MAX_SCOPE_MAPPING_PERMISSIONS,
    MAX_SCOPE_MAPPINGS, MAX_STEP_UP_RULES, Permission, PermissionActionRef, PermissionId,
    ResourceType, Role, RoleActionLimit, RoleActionRef, RoleLimitCountScope, RoleLimitCountSource,
    RoleLimitEnforcementMode, RoleLimitThresholds, RolePermission, Scope, ScopeMappingEntry,
    StepUpConfig, StepUpRule, ValidationError,
    configuration::{
        configuration_model::{ActionPatternCache, expand_action_patterns_cached},
        constants::{ACTION_MAX, RESOURCE_TYPE_MAX},
    },
};

#[test]
fn given_temporary_required_role_policy_without_maximum_when_validated_then_rejected() {
    let mut model = base_model();
    model.roles[0].assignment_policy = AccessAssignmentPolicySpec {
        assignment_mode: AccessAssignmentMode::TemporaryRequired,
        maximum_duration_seconds: None,
    };

    let errors = model
        .validate()
        .expect_err("temporary-required policy must have a maximum");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::RequiredFieldMissing("maximum_duration_seconds")
        )
    }));
}

#[test]
fn given_policy_with_server_metadata_when_deserialized_then_rejected() {
    let error = serde_json::from_value::<AccessAssignmentPolicySpec>(serde_json::json!({
        "assignment_mode": "permanent_or_temporary",
        "maximum_duration_seconds": null,
        "revision": 2,
        "updated_at_ms": 1_700_000_000_000_i64,
        "updated_by": "server"
    }))
    .expect_err("desired policy must not accept server metadata");

    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn given_role_when_serialized_then_policy_contains_only_customer_fields() {
    let role = &base_model().roles[0];
    let policy = serde_json::to_value(&role.assignment_policy).expect("serialize desired policy");
    assert_eq!(
        policy,
        serde_json::json!({
            "assignment_mode": "permanent_or_temporary"
        })
    );
}

#[test]
fn given_temporary_policy_at_maximum_duration_when_serialized_then_duration_round_trips() {
    // Given a valid temporary assignment policy at its maximum duration.
    let maximum_duration =
        AccessAssignmentDurationSeconds::try_new(MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS)
            .expect("the published maximum duration must be valid");
    let policy = AccessAssignmentPolicySpec::try_new(
        AccessAssignmentMode::TemporaryRequired,
        Some(maximum_duration),
    )
    .expect("a temporary policy with a maximum duration must validate");

    // When the policy is serialized and deserialized through its public JSON
    // shape.
    let encoded = serde_json::to_value(&policy).expect("temporary policy should serialize");
    let decoded = serde_json::from_value::<AccessAssignmentPolicySpec>(encoded.clone())
        .expect("serialized temporary policy should deserialize");

    // Then the maximum duration and complete customer policy are preserved
    // exactly.
    assert_eq!(
        encoded["maximum_duration_seconds"],
        serde_json::json!(MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS)
    );
    assert_eq!(decoded, policy);
    assert_eq!(decoded.maximum_duration_seconds, Some(maximum_duration));
}

#[test]
fn given_wildcard_catalog_identifiers_when_validated_then_catalog_boundary_rejects_them() {
    // Given catalog identifiers that wildcard expansion could otherwise match.
    let mut model = base_model();
    model.resource_types[0].id = "repo*".into();
    model.resource_types[0].actions[0].name = "read*".into();
    model.permissions[0].actions = vec![PermissionActionRef {
        resource_type: "repo*".into(),
        action_name: "read*".into(),
    }];
    model.roles[0].actions = vec![RoleActionRef {
        resource_type: "repo*".into(),
        action_name: "read*".into(),
        scopes: vec![Scope::Tenant],
        limit: None,
    }];

    // When validation runs before wildcard expansion is converted to exact
    // references.
    let errors = model
        .validate()
        .expect_err("wildcard-looking catalog identifiers must fail at the catalog boundary");

    // Then both public catalog strings are rejected before expansion can accept
    // them.
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "resource_types[].id"
                && message == "catalog identifiers must not contain wildcards"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "resource_types[].actions[].name"
                && message == "catalog identifiers must not contain wildcards"
    )));
}

#[test]
fn given_empty_entity_fields_when_validated_then_each_entity_reports_its_boundary_error() {
    // Given a configuration containing empty identifiers and collections.
    let mut model = base_model();
    model.resource_types.push(ResourceType {
        id: String::new(),
        name: String::new(),
        description: None,
        actions: vec![crate::ActionDefinition {
            name: String::new(),
            description: None,
        }],
        context_schema: None,
    });
    model.permissions.push(Permission {
        id: String::new(),
        name: String::new(),
        description: None,
        actions: Vec::new(),
        not_actions: Vec::new(),
    });
    model.roles.push(Role {
        id: String::new(),
        name: String::new(),
        description: None,
        permissions: Vec::new(),
        actions: Vec::new(),
        not_actions: Vec::new(),
        assignment_policy: permanent_policy_spec(),
    });

    // When validation runs at the customer configuration boundary.
    let errors = model
        .validate()
        .expect_err("empty entity fields must be rejected");

    // Then every owning validator reports its malformed input.
    for field in [
        "resource_types[].id",
        "resource_types[].name",
        "resource_types[].actions[].name",
        "permissions[].id",
        "permissions[].name",
    ] {
        assert!(
            errors.iter().any(|error| matches!(
                error,
                ValidationError::OutOfRange { field: actual, .. } if *actual == field
            )),
            "missing range error for {field}"
        );
    }
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "permissions[].actions" && message.contains("at least one")
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::OutOfRange { field, .. } if *field == "roles[].id"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::OutOfRange { field, .. } if *field == "roles[].name"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "roles[]" && message.contains("permissions or actions")
    )));
}

#[test]
fn given_oversized_nested_collections_when_validated_then_each_limit_is_reported() {
    // Given nested action, scope, and permission collections above their
    // contracts.
    let mut model = base_model();
    let permission_action = || PermissionActionRef {
        resource_type: "repo".into(),
        action_name: "read".into(),
    };
    model.permissions[0].actions = vec![permission_action(); MAX_PERMISSION_ACTION_REFS + 1];
    model.permissions[0].not_actions = vec![permission_action(); MAX_PERMISSION_ACTION_REFS + 1];

    let role_permission = || RolePermission {
        permission_id: PermissionId::new("repo:read".to_string()).expect("known permission id"),
        scopes: Vec::new(),
    };
    let role_action = || RoleActionRef {
        resource_type: "repo".into(),
        action_name: "read".into(),
        scopes: Vec::new(),
        limit: None,
    };
    let mut permissions = vec![role_permission(); MAX_ROLE_PERMISSION_REFS + 1];
    permissions[0].scopes = vec![Scope::Tenant; MAX_ROLE_ENTRY_SCOPES + 1];
    let mut actions = vec![role_action(); MAX_ROLE_ACTION_REFS + 1];
    actions[0].scopes = vec![Scope::Tenant; MAX_ROLE_ENTRY_SCOPES + 1];
    let mut not_actions = vec![role_action(); MAX_ROLE_ACTION_REFS + 1];
    not_actions[0].scopes = vec![Scope::Tenant; MAX_ROLE_ENTRY_SCOPES + 1];
    model.roles.push(Role {
        id: "limited_role".into(),
        name: "limited_role".into(),
        description: None,
        permissions,
        actions,
        not_actions,
        assignment_policy: permanent_policy_spec(),
    });

    // When validation checks each nested collection.
    let errors = model
        .validate()
        .expect_err("oversized nested collections must be rejected");

    // Then every limit carries its owning resource, ceiling, and observed
    // count.
    for (expected_resource, expected_limit, expected_actual) in [
        (
            "permission_actions",
            MAX_PERMISSION_ACTION_REFS,
            MAX_PERMISSION_ACTION_REFS + 1,
        ),
        (
            "permission_not_actions",
            MAX_PERMISSION_ACTION_REFS,
            MAX_PERMISSION_ACTION_REFS + 1,
        ),
        (
            "role_permissions",
            MAX_ROLE_PERMISSION_REFS,
            MAX_ROLE_PERMISSION_REFS + 1,
        ),
        (
            "role_actions",
            MAX_ROLE_ACTION_REFS,
            MAX_ROLE_ACTION_REFS + 1,
        ),
        (
            "role_not_actions",
            MAX_ROLE_ACTION_REFS,
            MAX_ROLE_ACTION_REFS + 1,
        ),
        (
            "role_permission_scopes",
            MAX_ROLE_ENTRY_SCOPES,
            MAX_ROLE_ENTRY_SCOPES + 1,
        ),
        (
            "role_action_scopes",
            MAX_ROLE_ENTRY_SCOPES,
            MAX_ROLE_ENTRY_SCOPES + 1,
        ),
        (
            "role_not_action_scopes",
            MAX_ROLE_ENTRY_SCOPES,
            MAX_ROLE_ENTRY_SCOPES + 1,
        ),
    ] {
        assert!(
            errors.iter().any(|error| matches!(
                error,
                ValidationError::LimitExceeded {
                    resource,
                    limit,
                    actual
                } if *resource == expected_resource
                    && *limit == expected_limit
                    && *actual == expected_actual
            )),
            "missing exact limit error for {expected_resource}"
        );
    }
}

#[test]
fn given_oversized_scope_and_step_up_collections_when_validated_then_limits_are_reported() {
    // Given scope mappings and step-up rules beyond their bounded cardinality.
    let mut model = base_model();
    let mut zero_age_rule = StepUpRule::require_acr("zero_age", "Zero age", AcrLevel::MultiFactor);
    zero_age_rule.max_auth_age_seconds = Some(0);
    zero_age_rule.max_mfa_age_seconds = Some(0);
    let mut step_up_rules = vec![zero_age_rule];
    step_up_rules.extend((0..MAX_STEP_UP_RULES).map(|index| {
        StepUpRule::require_acr(&format!("rule_{index}"), "Rule", AcrLevel::MultiFactor)
    }));
    model.step_up_rules = step_up_rules;

    let overfull_entry = ScopeMappingEntry {
        scope: "repo:read".into(),
        permissions: vec!["repo:read".into(); MAX_SCOPE_MAPPING_PERMISSIONS + 1],
        includes: vec!["repo:read".into(); MAX_SCOPE_MAPPING_INCLUDES + 1],
    };
    model.scope_mappings = vec![overfull_entry];
    model
        .scope_mappings
        .extend((0..MAX_SCOPE_MAPPINGS).map(|index| ScopeMappingEntry {
            scope: format!("scope_{index}"),
            permissions: vec!["repo:read".into()],
            includes: Vec::new(),
        }));
    model.scope_mappings[1].scope = "repo:read".into();
    model.scope_mappings.push(ScopeMappingEntry {
        scope: String::new(),
        permissions: vec!["repo:read".into()],
        includes: Vec::new(),
    });

    // When validation checks collection cardinality and step-up ages.
    let errors = model
        .validate()
        .expect_err("oversized scope and step-up collections must be rejected");

    // Then bounded collections and zero freshness windows are rejected
    // explicitly.
    for (expected_resource, expected_limit, expected_actual) in [
        ("scope_mappings", MAX_SCOPE_MAPPINGS, MAX_SCOPE_MAPPINGS + 2),
        (
            "scope_mapping_permissions",
            MAX_SCOPE_MAPPING_PERMISSIONS,
            MAX_SCOPE_MAPPING_PERMISSIONS + 1,
        ),
        (
            "scope_mapping_includes",
            MAX_SCOPE_MAPPING_INCLUDES,
            MAX_SCOPE_MAPPING_INCLUDES + 1,
        ),
        ("step_up_rules", MAX_STEP_UP_RULES, MAX_STEP_UP_RULES + 1),
    ] {
        assert!(
            errors.iter().any(|error| matches!(
                error,
                ValidationError::LimitExceeded {
                    resource,
                    limit,
                    actual
                } if *resource == expected_resource
                    && *limit == expected_limit
                    && *actual == expected_actual
            )),
            "missing exact limit error for {expected_resource}"
        );
    }
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "step_up_rules[].max_auth_age_seconds" && message == "must be > 0"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "step_up_rules[].max_mfa_age_seconds" && message == "must be > 0"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::OutOfRange { field, message }
            if *field == "scope_mappings[].scope"
                && message == "must be 1..=128 characters"
    )));
}

#[test]
fn given_step_up_config_for_unknown_targets_when_validated_then_references_fail_closed() {
    // Given an action map with an unknown resource, rule, and empty action
    // name.
    let mut model = base_model();
    let mut action_rules = HashMap::new();
    action_rules.insert(String::new(), "missing_action_rule".into());
    model.step_up_config.insert(
        "missing_resource".into(),
        StepUpConfig {
            default_rule: Some("missing_default_rule".into()),
            action_rules,
        },
    );

    // When validation resolves the step-up configuration references.
    let errors = model
        .validate()
        .expect_err("unknown step-up targets must be rejected");

    // Then no missing target or empty action is accepted.
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "resource_type" && id == "missing_resource"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "step_up_rule" && id == "missing_default_rule"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::InvalidFormat { field, message }
            if *field == "step_up_config[].action_rules" && message.contains("non-empty")
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "resource_type_action" && id == "missing_resource:"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "step_up_rule" && id == "missing_action_rule"
    )));
}

#[test]
fn given_empty_authn_provider_urls_when_validated_then_all_provider_boundaries_fail_closed() {
    // Given the provider cardinality limit and one malformed provider.
    let mut model = base_model();
    model.authn_providers = (0..=MAX_AUTHN_PROVIDERS)
        .map(|_| AuthnProviderConfig {
            issuer: "https://issuer.example.test".into(),
            jwks_uri: "https://issuer.example.test/jwks.json".into(),
            algorithms: Some(vec!["RS256".into()]),
            audiences: None,
            subject_claim: "sub".into(),
            org_claim: None,
            cache_ttl_seconds: 300,
        })
        .collect();
    model.authn_providers[0] = AuthnProviderConfig {
        issuer: String::new(),
        jwks_uri: String::new(),
        algorithms: Some(vec!["RS256".into()]),
        audiences: None,
        subject_claim: String::new(),
        org_claim: Some(String::new()),
        cache_ttl_seconds: 0,
    };
    model.authn_providers[1].subject_claim = "s".repeat(59);

    // When provider validation parses and bounds each field.
    let errors = model
        .validate()
        .expect_err("malformed authentication providers must be rejected");

    // Then malformed URLs, claims, TTL, and provider count are all reported
    // exactly.
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::LimitExceeded {
            resource,
            limit,
            actual
        } if *resource == "authn_providers"
            && *limit == MAX_AUTHN_PROVIDERS
            && *actual == MAX_AUTHN_PROVIDERS + 1
    )));
    for (field, message) in [
        ("authn_providers[].issuer", "issuer must be non-empty"),
        ("authn_providers[].jwks_uri", "jwks_uri must be non-empty"),
        (
            "authn_providers[].subject_claim",
            "subject_claim must be non-empty",
        ),
        (
            "authn_providers[].org_claim",
            "org_claim must be non-empty when provided",
        ),
    ] {
        assert!(
            errors.iter().any(|error| matches!(
                error,
                ValidationError::InvalidFormat {
                    field: actual_field,
                    message: actual_message
                } if *actual_field == field && actual_message == message
            )),
            "missing exact provider error for {field}"
        );
    }
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::OutOfRange { field, message }
            if *field == "authn_providers[].subject_claim"
                && message == "must be 1..=58 characters"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::OutOfRange { field, message }
            if *field == "authn_providers[].cache_ttl_seconds"
                && message == "must be 1..=86400"
    )));
}

#[test]
fn given_unknown_action_references_when_validated_then_resource_and_action_errors_are_distinct() {
    // Given one action referring to an unknown resource and one to an unknown
    // action.
    let mut model = base_model();
    model.permissions[0].actions = vec![PermissionActionRef {
        resource_type: "missing".into(),
        action_name: "read".into(),
    }];
    model.permissions.push(Permission {
        id: "repo:unknown".into(),
        name: "repo_unknown".into(),
        description: None,
        actions: vec![PermissionActionRef {
            resource_type: "repo".into(),
            action_name: "missing".into(),
        }],
        not_actions: Vec::new(),
    });

    // When validation resolves every action reference.
    let errors = model
        .validate()
        .expect_err("unknown action references must be rejected");

    // Then callers can distinguish a missing resource from a missing action.
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "resource_type" && id == "missing"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::ReferenceNotFound { entity_type, id }
            if *entity_type == "resource_type_action" && id == "repo:missing"
    )));
}

#[test]
fn given_matching_typed_resource_scope_when_validated_then_scope_and_typestate_are_preserved() {
    // Given a typed scope whose resource type matches the granted action.
    let mut model = base_model();
    model.roles[0].permissions[0].scopes = vec![Scope::resource("REPO")];
    model.roles[0].actions[0].scopes = vec![Scope::resource("repo")];

    // When the model is converted to its validated typestate.
    let validated = model
        .into_validated()
        .expect("matching typed scopes must validate");
    let inner = validated.into_inner();

    // Then the canonical expanded model retains both typed scope grants.
    assert_eq!(
        inner.roles[0].permissions[0].scopes,
        vec![Scope::resource("REPO")]
    );
    assert_eq!(
        inner.roles[0].actions[0].scopes,
        vec![Scope::resource("repo")]
    );
}

#[test]
fn given_configuration_without_version_when_deserialized_then_schema_version_defaults() {
    // Given the minimum JSON shape with the optional version omitted.
    let payload = serde_json::json!({
        "resource_types": [],
        "permissions": [],
        "roles": []
    });

    // When serde loads the customer configuration.
    let model = serde_json::from_value::<ConfigurationModel>(payload)
        .expect("omitted version should use the schema default");

    // Then forward-compatible configurations start at version one.
    assert_eq!(model.version, 1);
}

#[test]
fn repeated_wildcard_expansion_reuses_the_catalog_match() {
    let resource_types = vec![ResourceType {
        id: "document".into(),
        name: "Document".into(),
        description: None,
        actions: (0..4)
            .map(|index| crate::ActionDefinition {
                name: format!("read-{index}"),
                description: None,
            })
            .collect(),
        context_schema: None,
    }];
    let mut cache = ActionPatternCache::new();

    let first = expand_action_patterns_cached(
        &mut cache,
        &resource_types,
        "document",
        "read-*",
        RESOURCE_TYPE_MAX,
        ACTION_MAX,
    )
    .expect("first wildcard expansion");
    let second = expand_action_patterns_cached(
        &mut cache,
        &resource_types,
        "DOCUMENT",
        "READ-*",
        RESOURCE_TYPE_MAX,
        ACTION_MAX,
    )
    .expect("cached wildcard expansion");

    assert_eq!(first, second);
    assert_eq!(
        cache.len(),
        1,
        "duplicate patterns must not rescan the catalog"
    );
}

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
fn recent_auth_step_up_rules_require_a_freshness_window() {
    let mut model = base_model();
    model.step_up_rules = vec![StepUpRule::require_acr(
        "recent",
        "Recent authentication",
        AcrLevel::RecentAuth,
    )];

    let errors = model
        .validate()
        .expect_err("RecentAuth without a freshness window must be rejected");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "step_up_rules[].max_auth_age_seconds"
                    && message.contains("required")
        )
    }));
}

#[test]
fn nested_permission_action_collections_are_bounded() {
    let mut model = base_model();
    model.permissions[0].actions = (0..=MAX_PERMISSION_ACTION_REFS)
        .map(|index| PermissionActionRef {
            resource_type: "repo".into(),
            action_name: if index == 0 {
                "read".into()
            } else {
                format!("action_{index}")
            },
        })
        .collect();

    let errors = model
        .validate()
        .expect_err("nested permission collections must be bounded");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::LimitExceeded { resource, limit, actual }
                if *resource == "permission_actions"
                    && *limit == MAX_PERMISSION_ACTION_REFS
                    && *actual == MAX_PERMISSION_ACTION_REFS + 1
        )
    }));
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
        assignment_policy: permanent_policy_spec(),
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
        assignment_policy: permanent_policy_spec(),
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
fn resource_scope_type_must_match_the_granted_resource() {
    let mut model = base_model();
    model.resource_types.push(ResourceType {
        id: "other".into(),
        name: "other".into(),
        description: None,
        actions: vec![crate::ActionDefinition {
            name: "read".into(),
            description: None,
        }],
        context_schema: None,
    });
    model.roles[0].permissions[0].scopes = vec![Scope::resource("other")];

    let errors = model
        .validate()
        .expect_err("public validation must reject an untyped resource grant");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "roles[].permissions[].scopes"
                    && message.contains("must match")
        )
    }));
}

#[test]
fn resource_scope_rejects_a_permission_spanning_multiple_resource_types() {
    let mut model = base_model();
    model.resource_types.push(ResourceType {
        id: "other".into(),
        name: "other".into(),
        description: None,
        actions: vec![crate::ActionDefinition {
            name: "read".into(),
            description: None,
        }],
        context_schema: None,
    });
    model.permissions[0].actions.push(PermissionActionRef {
        resource_type: "other".into(),
        action_name: "read".into(),
    });
    model.roles[0].permissions[0].scopes = vec![Scope::resource("repo")];

    let errors = model
        .into_validated()
        .expect_err("typed resource scope cannot be reused across heterogeneous actions");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "roles[].permissions[].scopes"
                    && message.contains("only granted resource type")
        )
    }));
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
            assignment_policy: permanent_policy_spec(),
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
    model
        .resource_types
        .extend((0..MAX_RESOURCE_TYPES).map(|index| ResourceType {
            id: format!("repo_{index}"),
            name: format!("Repository {index}"),
            description: None,
            actions: vec![crate::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }));

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
    assert!(errs.iter().any(|e| {
        matches!(
            e,
            ValidationError::LimitExceeded {
                resource,
                limit,
                actual
            } if *resource == "resource_types"
                && *limit == MAX_RESOURCE_TYPES
                && *actual == MAX_RESOURCE_TYPES + 1
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
        limit: None,
    }];

    assert!(model.validate().is_ok());
}

#[test]
fn given_invalid_role_action_limit_when_validating_configuration_then_configuration_is_rejected() {
    let mut model = base_model();
    let mut invalid = RoleActionLimit::try_new(
        "projects",
        5,
        "projects",
        RoleLimitCountScope::Tenant,
        RoleLimitCountSource::Capacity,
        RoleLimitEnforcementMode::Hard,
        120,
        RoleLimitThresholds::default(),
    )
    .expect("valid limit");
    invalid.count_source = RoleLimitCountSource::CustomerSupplied;
    model.roles[0].actions[0].limit = Some(invalid);

    let errors = model
        .validate()
        .expect_err("invalid customer-supplied hard policy must be rejected");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, .. }
                if *field == "limit.enforcement_mode"
        )
    }));
}

#[test]
fn given_limit_on_not_action_when_validating_configuration_then_configuration_is_rejected() {
    let mut model = base_model();
    let valid = RoleActionLimit::try_new(
        "projects",
        5,
        "projects",
        RoleLimitCountScope::Tenant,
        RoleLimitCountSource::Capacity,
        RoleLimitEnforcementMode::Hard,
        120,
        RoleLimitThresholds::default(),
    )
    .expect("valid limit");
    model.roles[0].not_actions = vec![RoleActionRef {
        resource_type: "repo".into(),
        action_name: "read".into(),
        scopes: vec![Scope::Tenant],
        limit: Some(valid),
    }];

    let errors = model
        .validate()
        .expect_err("deny entries cannot carry granting limits");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, .. }
                if *field == "roles[].not_actions[].limit"
        )
    }));
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
    model.roles[0].actions = vec![RoleActionRef {
        resource_type: "repo".into(),
        action_name: "*".into(),
        scopes: vec![Scope::Tenant],
        limit: None,
    }];

    let validated = model.into_validated().expect("config should validate");
    let permission = validated
        .permissions
        .iter()
        .find(|entry| entry.id == "repo:read")
        .expect("permission should exist");

    assert_eq!(permission.actions.len(), 2);
    assert_eq!(permission.actions[0].action_name, "read");
    assert_eq!(permission.actions[1].action_name, "write");
    assert_eq!(validated.roles[0].actions.len(), 2);
    assert_eq!(validated.roles[0].actions[0].action_name, "read");
    assert_eq!(validated.roles[0].actions[1].action_name, "write");
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
fn given_authn_provider_urls_with_whitespace_when_validating_then_https_fields_fail_closed() {
    let mut model = base_model();
    model.authn_providers.push(AuthnProviderConfig {
        issuer: "https://issuer.example.test ".into(),
        jwks_uri: "https://issuer.example.test/\njwks.json".into(),
        algorithms: None,
        audiences: None,
        subject_claim: "sub".into(),
        org_claim: None,
        cache_ttl_seconds: 300,
    });

    let errors = model
        .validate()
        .expect_err("whitespace in authn provider URLs must fail validation");

    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "authn_providers[].issuer" && message == "issuer must be https"
        )
    }));
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, message }
                if *field == "authn_providers[].jwks_uri" && message == "jwks_uri must be https"
        )
    }));
}

#[test]
fn authn_provider_declared_bounds_are_enforced() {
    let mut model = base_model();
    model.authn_providers.push(AuthnProviderConfig {
        issuer: format!("https://{}", "i".repeat(2048)),
        jwks_uri: format!("https://{}", "j".repeat(2048)),
        algorithms: Some((0..=6).map(|_| "RS256".to_string()).collect()),
        audiences: Some((0..=25).map(|_| "auxfn-api".to_string()).collect()),
        subject_claim: " ".into(),
        org_claim: Some("o".repeat(59)),
        cache_ttl_seconds: 86_401,
    });

    let errors = model
        .validate()
        .expect_err("authn provider values outside the published bounds must fail");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::OutOfRange { field, .. }
                if *field == "authn_providers[].issuer"
        )
    }));
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::OutOfRange { field, .. }
                if *field == "authn_providers[].jwks_uri"
        )
    }));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::LimitExceeded {
            resource,
            limit,
            actual
        } if *resource == "authn_providers[].algorithms" && *limit == 6 && *actual == 7
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        ValidationError::LimitExceeded {
            resource,
            limit,
            actual
        } if *resource == "authn_providers[].audiences" && *limit == 25 && *actual == 26
    )));
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::InvalidFormat { field, .. }
                if *field == "authn_providers[].subject_claim"
        )
    }));
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::OutOfRange { field, .. }
                if *field == "authn_providers[].org_claim"
        )
    }));
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::OutOfRange { field, .. }
                if *field == "authn_providers[].cache_ttl_seconds"
        )
    }));
}

#[test]
fn resource_type_id_uses_the_shared_identifier_bound() {
    let mut model = base_model();
    model.resource_types[0].id = "r".repeat(59);

    let errors = model
        .validate()
        .expect_err("resource type ids must respect the shared identifier bound");
    assert!(errors.iter().any(|error| {
        matches!(
            error,
            ValidationError::OutOfRange { field, .. }
                if *field == "resource_types[].id"
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
                limit: None,
            }],
            not_actions: vec![],
            assignment_policy: permanent_policy_spec(),
        }],
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
}

fn permanent_policy_spec() -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec::try_new(AccessAssignmentMode::PermanentOrTemporary, None)
        .expect("valid permanent-or-temporary policy")
}
