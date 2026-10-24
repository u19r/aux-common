use std::{collections::HashMap, process::Command};

use alloc_counter::AllocationGuard;
use authz_types::{
    AccessAssignmentMode, AccessAssignmentPolicySpec, ActionDefinition, ConfigurationModel,
    FineGrainedScopes, MAX_PERMISSIONS, Permission, PermissionActionRef, PermissionId,
    ResourceType, Role, RoleActionRef, RolePermission, Scope, TokenContext, TokenScopeConfig,
};
use chrono::Utc;

use crate::{
    ActionPolicyDecision, EvaluationRuntime, PermissionBits, RoleBits, action_policy_decision_bits,
    best_permission_for_action_with_bits,
};

const ISOLATED_ALLOC_GUARD_ENV: &str = "AUTHZ_RUNTIME_ISOLATED_ALLOC_GUARD";

#[test]
fn given_compiled_permission_and_role_masks_when_evaluating_actions_then_denies_and_allows_are_preserved()
 {
    // Given permissions and direct role actions that include both grants and
    // denials.
    let runtime = runtime_with_compiled_action_masks();
    let mut permissions = PermissionBits::default();
    permissions.set(0);
    permissions.set(1);
    let mut checked_roles = RoleBits::default();
    checked_roles.set(0);

    // When the public action-policy boundary evaluates each compiled
    // descriptor.
    let read = action_policy_decision_bits(
        &runtime,
        "document",
        "read",
        &permissions,
        &checked_roles,
        true,
    );
    let write = action_policy_decision_bits(
        &runtime,
        "document",
        "write",
        &permissions,
        &checked_roles,
        true,
    );
    let inspect = action_policy_decision_bits(
        &runtime,
        "document",
        "inspect",
        &PermissionBits::default(),
        &checked_roles,
        true,
    );
    let uncatalogued = action_policy_decision_bits(
        &runtime,
        "document",
        "delete",
        &permissions,
        &checked_roles,
        true,
    );

    // Then explicit permission denials win, role grants remain usable, and
    // unknown actions fail open only at the policy-selection layer for the
    // caller's Cedar decision to resolve.
    assert_eq!(read, ActionPolicyDecision::AllowMatched);
    assert_eq!(write, ActionPolicyDecision::DenyMatched);
    assert_eq!(inspect, ActionPolicyDecision::AllowMatched);
    assert_eq!(uncatalogued, ActionPolicyDecision::NoPolicyAllow);
}

#[test]
fn given_equal_permission_candidates_when_selecting_the_best_permission_then_ids_break_the_tie() {
    // Given two permissions with the same action score and the same allowed
    // action, inserted in the reverse of identifier order.
    let runtime = runtime_with_compiled_action_masks();
    let mut permissions = PermissionBits::default();
    permissions.set(0);
    permissions.set(1);

    // When the public best-permission boundary selects the candidate.
    let selected = best_permission_for_action_with_bits(&runtime, "document", "read", &permissions);

    // Then selection is deterministic by the stable permission identifier.
    assert_eq!(selected.as_deref(), Some("document:alpha"));
}

#[test]
fn given_unexpired_full_access_token_when_resolving_permissions_then_public_wrapper_returns_all_bits()
 {
    // Given a runtime and a full-access token without an expiry.
    let runtime = runtime_with_compiled_action_masks();
    let mut user_permissions = PermissionBits::default();
    user_permissions.set(0);
    user_permissions.set(1);
    let token = TokenContext::new(
        "token_full".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::full_access(),
    );

    // When the public convenience method resolves the token ceiling.
    let resolved = runtime.resolve_token_permissions(&user_permissions, &token);

    // Then the token remains valid and cannot accidentally lose a caller
    // permission.
    assert!(resolved.is_valid);
    assert!(resolved.invalid_reason.is_none());
    assert!(resolved.permissions.contains(0));
    assert!(resolved.permissions.contains(1));
}

#[test]
fn given_persisted_token_ceiling_when_resolving_permissions_then_unknown_ids_cannot_grant_access() {
    // Given a token whose creation-time ceiling names one current and one
    // obsolete permission.
    let runtime = runtime_with_compiled_action_masks();
    let mut user_permissions = PermissionBits::default();
    user_permissions.set(0);
    user_permissions.set(1);
    let token = TokenContext::new(
        "token_scoped".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
            .expect("valid coarse scope")
            .with_resolved_permissions(vec![
                "document:alpha".to_string(),
                "document:removed".to_string(),
            ])
            .expect("valid persisted ceiling"),
    );

    // When the public runtime resolves the persisted ceiling at a fixed time.
    let resolved = runtime.resolve_token_permissions_at(&user_permissions, &token, Utc::now());

    // Then only the permission still present in the validated configuration
    // survives.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(1));
    assert!(!resolved.permissions.contains(0));
}

#[test]
fn given_empty_scope_strings_with_persisted_ceiling_when_resolving_then_denies_without_grant() {
    // When a caller tries to attach a ceiling without a requested scope.
    let result = TokenScopeConfig::with_scopes(Vec::new())
        .expect("an empty requested scope list is valid by itself")
        .with_resolved_permissions(vec!["document:alpha".to_string()]);

    // Then the immutable policy boundary rejects the contradictory state before
    // an evaluator can receive it.
    assert!(result.is_err());
}

#[test]
fn given_stale_permission_bit_when_resolving_fine_grained_token_then_unknown_bit_is_ignored() {
    // Given a caller bitset that contains a permission no longer present in
    // this runtime catalog.
    let runtime = runtime_with_compiled_action_masks();
    let mut user_permissions = PermissionBits::default();
    user_permissions.set(1);
    user_permissions.set(MAX_PERMISSIONS - 1);
    let token = TokenContext::new(
        "token_fine_grained".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_permissions: HashMap::from([(
                "document".to_string(),
                vec!["document:alpha".to_string()],
            )]),
            ..FineGrainedScopes::default()
        })
        .expect("valid fine-grained scope"),
    );

    // When the public resolver intersects the fine-grained ceiling.
    let resolved = runtime.resolve_token_permissions_at(&user_permissions, &token, Utc::now());

    // Then the current permission is retained and stale state cannot grant or
    // panic.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(1));
    assert!(!resolved.permissions.contains(MAX_PERMISSIONS - 1));
}

#[test]
fn given_invalid_constructed_scope_when_building_then_runtime_cannot_receive_it() {
    // Given a selected-resource policy whose shape is impossible to satisfy.
    let result = TokenScopeConfig::fine_grained(FineGrainedScopes {
        resource_selection: authz_types::ResourceSelection::Selected,
        selected_resources: Vec::new(),
        ..FineGrainedScopes::default()
    });

    // Then the evaluator cannot receive a malformed scope configuration.
    assert!(result.is_err());
}

#[test]
fn given_valid_scope_when_resolving_repeatedly_then_cached_policy_path_allocates_nothing() {
    if std::env::var_os(ISOLATED_ALLOC_GUARD_ENV).is_none() {
        let test_executable = std::env::current_exe().expect("current test executable");
        let output = Command::new(test_executable)
            .arg("--exact")
            .arg(
                "evaluation_runtime_tests::given_valid_scope_when_resolving_repeatedly_then_cached_policy_path_allocates_nothing",
            )
            .arg("--test-threads=1")
            .env(ISOLATED_ALLOC_GUARD_ENV, "1")
            .output()
            .expect("run isolated allocation guard");
        assert!(
            output.status.success(),
            "isolated allocation guard failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Given a valid scoped token and an already-built evaluator catalog.
    let runtime = runtime_with_compiled_action_masks();
    let mut user_permissions = PermissionBits::default();
    user_permissions.set(0);
    let token = TokenContext::new(
        "token_cached_scope".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
            .expect("valid coarse scope"),
    );
    let now = Utc::now();
    let guard = AllocationGuard::start(
        module_path!(),
        "given_valid_scope_when_resolving_repeatedly_then_cached_policy_path_allocates_nothing",
        file!(),
        line!(),
        Some("cached_scope_resolution"),
    );

    // When the hot path resolves the same validated policy repeatedly.
    for _ in 0..128 {
        let resolved = runtime.resolve_token_permissions_at(&user_permissions, &token, now);
        assert!(resolved.is_valid);
        std::hint::black_box(resolved.permissions);
    }
    let report = guard.finish();

    // Then construction-time validation is not repeated and the valid path
    // does not allocate per token resolution.
    assert_eq!(report.allocation_count, 0);
    assert_eq!(report.allocated_bytes, 0);
}

#[test]
fn given_built_runtime_when_reading_public_configuration_then_original_catalog_is_available() {
    // Given a runtime built from the shared fixture.
    let runtime = runtime_with_compiled_action_masks();

    // When callers inspect the public configuration snapshot.
    let config = runtime.config();

    // Then the validated catalog remains available without exposing runtime
    // internals.
    assert_eq!(config.resource_types.len(), 1);
    assert_eq!(config.permissions.len(), 2);
    assert_eq!(config.roles.len(), 1);
}

fn runtime_with_compiled_action_masks() -> EvaluationRuntime {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "document".to_string(),
            name: "Document".to_string(),
            description: None,
            actions: vec![action("read"), action("write"), action("inspect")],
            context_schema: None,
        }],
        permissions: vec![permission("document:beta"), permission("document:alpha")],
        roles: vec![Role {
            id: "operator".to_string(),
            name: "Operator".to_string(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:alpha").expect("valid permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![RoleActionRef {
                resource_type: "document".to_string(),
                action_name: "inspect".to_string(),
                scopes: vec![Scope::Tenant],
                limit: None,
            }],
            not_actions: vec![RoleActionRef {
                resource_type: "document".to_string(),
                action_name: "write".to_string(),
                scopes: vec![Scope::Tenant],
                limit: None,
            }],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    };
    let validated = config
        .into_validated()
        .expect("valid runtime configuration");
    let bundle = authz_cedar::compile_policy_bundle(&validated, 1).expect("compiled policy bundle");
    EvaluationRuntime::build(validated, &bundle).expect("evaluation runtime")
}

fn action(name: &str) -> ActionDefinition {
    ActionDefinition {
        name: name.to_string(),
        description: None,
    }
}

fn permission(id: &str) -> Permission {
    Permission {
        id: id.to_string(),
        name: id.to_string(),
        description: None,
        actions: vec![PermissionActionRef {
            resource_type: "document".to_string(),
            action_name: "read".to_string(),
        }],
        not_actions: vec![PermissionActionRef {
            resource_type: "document".to_string(),
            action_name: "write".to_string(),
        }],
    }
}

fn permanent_assignment_policy() -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec::try_new(AccessAssignmentMode::PermanentOrTemporary, None)
        .expect("valid assignment policy")
}
