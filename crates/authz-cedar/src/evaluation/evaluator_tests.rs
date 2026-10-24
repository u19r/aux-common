use std::{collections::HashMap, str::FromStr};

use authz_types::{
    AcrLevel, Action, BatchEvaluationRequest, ConfigurationModel, Context, PermissionActionRef,
    PermissionId, Resource, Scope, StepUpRule, Subject,
};
use serde_json::{Map, Value};

use crate::{
    BundleManifest, CedarEntityRef, CedarInternalContext, CedarResourceScope, CedarUidRegistry,
    CompiledBundle, EntityParentRef, PolicySlice, SchemaSlice, SliceMeta, compile_policy_bundle,
    evaluate as evaluate_untrusted, evaluate_batch,
    evaluate_batch_frame_action_with_policy_sets_error_diagnostics,
    evaluate_batch_owned_with_policy_sets, evaluate_batch_with_policy_sets,
    evaluate_owned_with_policy_sets, evaluate_owned_with_trusted_parents_and_policy_sets,
    evaluate_prepared_with_policy_sets, evaluate_with_policy_sets, parse_policy_sets,
    prepare_batch_frame_owned_with_registry_and_trusted_internal_context,
    prepare_evaluation_owned_with_trusted_parents,
    prepare_evaluation_owned_with_trusted_parents_and_internal_context, prepare_request_uids,
    validate_bundle_for_config, validate_bundle_integrity,
};

#[test]
fn typed_uid_construction_round_trips_all_validated_identifier_shapes() {
    let identifiers = [
        "quote\"id".to_string(),
        "slash/id".to_string(),
        "colon:id".to_string(),
        "unicode-用户-🚀".to_string(),
        "x".repeat(authz_types::MAX_IDENTIFIER_LEN),
    ];

    for identifier in identifiers {
        let request = authz_types::EvaluationRequest {
            subject: Subject::user(identifier.clone()),
            resource: Resource::new("document", identifier.clone()),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let uids = prepare_request_uids(&request).expect("typed UIDs");
        for uid in [uids.principal(), uids.action(), uids.resource()] {
            let reparsed = cedar_policy::EntityUid::from_str(&uid.to_string())
                .expect("rendered UID remains valid Cedar syntax");
            assert_eq!(&reparsed, uid);
        }
    }
}

use std::{hint::black_box, time::Instant};

use alloc_counter::AllocationGuard;
use authz_types::EvaluationRequest;
use cedar_policy::PolicySet;

const ITERATIONS: usize = 512;
const MAX_ALLOCATIONS_PER_RUN: u64 = 1_050_000;
const MAX_ALLOCATED_BYTES_PER_RUN: u64 = 320_000_000;
const ISOLATED_ALLOC_GUARD_ENV: &str = "AUTHZ_CEDAR_ISOLATED_ALLOC_GUARD";
const DIAGNOSTIC_ITERATIONS: usize = 10_000;

fn default_typed_internal_context() -> CedarInternalContext {
    CedarInternalContext {
        token_present: false,
        token_valid: true,
        token_resource_filter_enabled: false,
        token_resource_filter: Vec::new(),
        resource_scopes: Vec::new(),
        token_org_id_present: false,
        token_org_id: String::new(),
        token_owner_org_ids: Vec::new(),
        allowed_actions: Vec::new(),
        session_present: false,
        session_acr: 0,
        session_amr: Vec::new(),
        session_auth_age_present: false,
        session_auth_age_seconds: 0,
        session_mfa_age_present: false,
        session_mfa_age_seconds: 0,
    }
}

fn allocation_fixture() -> (crate::ParsedPolicySets, EvaluationRequest) {
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
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader")
                    .expect("permission id should be valid"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("config should validate");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle should compile");
    let parsed_policy_sets = parse_policy_sets(&bundle).expect("policy sets should parse");

    let request = EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    (parsed_policy_sets, request)
}

fn measure_direct_path(
    policy_sets: &crate::ParsedPolicySets,
    request: &EvaluationRequest,
) -> alloc_counter::AllocationReport<'static> {
    let guard = AllocationGuard::start(
        module_path!(),
        "authz_cedar_evaluate_with_policy_sets_direct_path",
        file!(),
        line!(),
        Some("direct"),
    );

    for _ in 0..ITERATIONS {
        let response = evaluate_with_policy_sets(policy_sets, request)
            .expect("direct evaluation should succeed");
        black_box(response.decision);
    }

    guard.finish()
}

fn measure_typed_internal_path(
    policy_sets: &crate::ParsedPolicySets,
    request: &EvaluationRequest,
) -> alloc_counter::AllocationReport<'static> {
    let guard = AllocationGuard::start(
        module_path!(),
        "authz_cedar_evaluate_with_policy_sets_direct_path",
        file!(),
        line!(),
        Some("typed_internal"),
    );

    for _ in 0..ITERATIONS {
        let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
            request.clone(),
            &[],
            &[],
            default_typed_internal_context(),
        )
        .expect("typed preparation should succeed");
        let response = evaluate_prepared_with_policy_sets(policy_sets, prepared)
            .expect("typed evaluation should succeed");
        black_box(response.decision);
    }

    guard.finish()
}

fn measure_owned_untrusted_path(
    policy_sets: &crate::ParsedPolicySets,
    request: &EvaluationRequest,
) -> alloc_counter::AllocationReport<'static> {
    let guard = AllocationGuard::start(
        module_path!(),
        "authz_cedar_evaluate_owned_untrusted_path",
        file!(),
        line!(),
        Some("owned_untrusted"),
    );

    for _ in 0..ITERATIONS {
        let response = evaluate_owned_with_policy_sets(policy_sets, request.clone())
            .expect("owned JSON evaluation should succeed");
        black_box(response.decision);
    }

    guard.finish()
}

#[test]
fn evaluate_with_policy_sets_direct_path_budget_tests() {
    if std::env::var_os(ISOLATED_ALLOC_GUARD_ENV).is_none() {
        let test_executable = std::env::current_exe().expect("current test executable");
        let output = std::process::Command::new(test_executable)
            .arg("--exact")
            .arg("evaluator_alloc_tests::evaluate_with_policy_sets_direct_path_budget_tests")
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

    // Baseline snapshot (2026-03-24, template-linked policy payloads,
    // ITERATIONS=512): direct_path: 965,457 allocs, 297,774,768 bytes
    let (policy_sets, request) = allocation_fixture();
    let report = measure_direct_path(&policy_sets, &request);
    let owned_untrusted_report = measure_owned_untrusted_path(&policy_sets, &request);
    let typed_report = measure_typed_internal_path(&policy_sets, &request);

    alloc_counter::emit_report(&report).expect("allocation report");
    alloc_counter::emit_report(&owned_untrusted_report).expect("allocation report");
    alloc_counter::emit_report(&typed_report).expect("allocation report");

    assert!(
        report.allocation_count <= MAX_ALLOCATIONS_PER_RUN,
        "allocation budget exceeded: actual={} budget={}",
        report.allocation_count,
        MAX_ALLOCATIONS_PER_RUN
    );
    assert!(
        report.allocated_bytes <= MAX_ALLOCATED_BYTES_PER_RUN,
        "byte budget exceeded: actual={} budget={}",
        report.allocated_bytes,
        MAX_ALLOCATED_BYTES_PER_RUN
    );
    assert!(
        typed_report.allocation_count <= MAX_ALLOCATIONS_PER_RUN,
        "typed internal allocation budget exceeded: actual={} budget={}",
        typed_report.allocation_count,
        MAX_ALLOCATIONS_PER_RUN
    );
    assert!(
        typed_report.allocated_bytes <= MAX_ALLOCATED_BYTES_PER_RUN,
        "typed internal byte budget exceeded: actual={} budget={}",
        typed_report.allocated_bytes,
        MAX_ALLOCATED_BYTES_PER_RUN
    );
}

fn diagnostic_fixture(policy: &str) -> (PolicySet, crate::PreparedCedarEvaluation) {
    let policies = PolicySet::from_str(policy).expect("diagnostic policies");
    let request = EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let prepared = crate::prepare_evaluation_owned(request).expect("prepared diagnostic request");
    (policies, prepared)
}

fn measure_diagnostics(
    label: &'static str,
    policies: &PolicySet,
    prepared: &crate::PreparedCedarEvaluation,
) -> (
    alloc_counter::AllocationReport<'static>,
    std::time::Duration,
) {
    let guard = AllocationGuard::start(
        module_path!(),
        "healthy_cedar_diagnostics_profile",
        file!(),
        line!(),
        Some(label),
    );
    let started_at = Instant::now();
    for _ in 0..DIAGNOSTIC_ITERATIONS {
        let result = crate::evaluation::evaluate_prepared_with_policy_set_error_diagnostics(
            policies, prepared,
        );
        black_box(result);
    }
    let elapsed = started_at.elapsed();
    (guard.finish(), elapsed)
}

fn measure_explicit_diagnostics(
    policies: &PolicySet,
    prepared: &crate::PreparedCedarEvaluation,
) -> (
    alloc_counter::AllocationReport<'static>,
    std::time::Duration,
) {
    let guard = AllocationGuard::start(
        module_path!(),
        "healthy_cedar_diagnostics_profile",
        file!(),
        line!(),
        Some("explicit_allow"),
    );
    let started_at = Instant::now();
    for _ in 0..DIAGNOSTIC_ITERATIONS {
        let result =
            crate::evaluation::evaluate_prepared_with_policy_set_diagnostics(policies, prepared);
        black_box(result);
    }
    let elapsed = started_at.elapsed();
    (guard.finish(), elapsed)
}

#[test]
#[ignore = "optimization profile"]
fn healthy_cedar_diagnostics_profile() {
    let (allow_policies, allow_prepared) =
        diagnostic_fixture(r#"@id("allow") permit(principal, action, resource);"#);
    let (deny_policies, deny_prepared) =
        diagnostic_fixture(r#"@id("deny") forbid(principal, action, resource);"#);
    let (allow_report, allow_elapsed) =
        measure_diagnostics("allow", &allow_policies, &allow_prepared);
    let (deny_report, deny_elapsed) = measure_diagnostics("deny", &deny_policies, &deny_prepared);
    let (explicit_report, explicit_elapsed) =
        measure_explicit_diagnostics(&allow_policies, &allow_prepared);

    alloc_counter::emit_report(&allow_report).expect("allocation report");
    alloc_counter::emit_report(&deny_report).expect("allocation report");
    alloc_counter::emit_report(&explicit_report).expect("allocation report");
    eprintln!(
        "ac3_001|mode=allow|iterations={DIAGNOSTIC_ITERATIONS}|elapsed_ns={}",
        allow_elapsed.as_nanos(),
    );
    eprintln!(
        "ac3_001|mode=deny|iterations={DIAGNOSTIC_ITERATIONS}|elapsed_ns={}",
        deny_elapsed.as_nanos(),
    );
    eprintln!(
        "ac3_001|mode=explicit_allow|iterations={DIAGNOSTIC_ITERATIONS}|elapsed_ns={}",
        explicit_elapsed.as_nanos(),
    );
}

#[test]
fn prepared_uid_registry_matches_dynamic_uid_construction_for_every_subject_type() {
    let config = config_with_scope(Scope::Tenant);
    let registry = CedarUidRegistry::new(&config).expect("prepared uid registry");
    let subjects = [
        Subject::user("subject"),
        Subject::group("subject"),
        Subject::role("subject"),
        Subject::api_key("subject"),
        Subject::machine("subject"),
        Subject::protocol("subject"),
    ];

    for subject in subjects {
        let request = authz_types::EvaluationRequest {
            subject,
            resource: Resource::new("document", "doc1"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let dynamic = prepare_request_uids(&request).expect("dynamic uids");
        let prepared = registry.request_uids(&request).expect("prepared uids");

        assert_eq!(prepared.resource_type(), dynamic.resource_type());
        assert_eq!(prepared.principal(), dynamic.principal());
        assert_eq!(prepared.action(), dynamic.action());
        assert_eq!(prepared.resource(), dynamic.resource());
    }
}

/// Test-only evaluation through the trusted enrichment path: request
/// context parents are honored as trusted and the request `_authz` context
/// is converted to typed internal context. Production wire requests must
/// use [`evaluate_untrusted`] (the `evaluate` API), which rejects enriched
/// inputs before evaluation. The distinct name keeps the two trust levels
/// from being confused.
fn evaluate_with_test_trust(
    bundle: &crate::CompiledBundle,
    request: &authz_types::EvaluationRequest,
) -> Result<authz_types::EvaluationResponse, crate::CedarError> {
    let policy_sets = parse_policy_sets(bundle)?;
    let subject_parents = parent_refs_from_test_context(request, "subject_parents");
    let resource_parents = parent_refs_from_test_context(request, "resource_parents");
    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request.clone(),
        &subject_parents,
        &resource_parents,
        typed_internal_context_from_test_context(request),
    )?;
    evaluate_prepared_with_policy_sets(&policy_sets, prepared)
}

fn parent_refs_from_test_context(
    request: &authz_types::EvaluationRequest,
    key: &str,
) -> Vec<EntityParentRef> {
    request
        .context
        .as_ref()
        .and_then(|context| context.attributes.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parent| {
            Some(EntityParentRef {
                parent_type: parent.get("type")?.as_str()?.to_string(),
                parent_id: parent.get("id")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn default_internal_context() -> Value {
    serde_json::json!({
        "token_present": false,
        "token_valid": true,
        "token_resource_filter_enabled": false,
        "token_resource_filter": [],
        "token_org_id_present": false,
        "token_org_id": "",
        "token_owner_org_ids": [],
        "allowed_actions": [],
        "resource_scopes": [],
        "session_present": false,
        "session_acr": 0,
        "session_amr": [],
        "session_auth_age_present": false,
        "session_auth_age_seconds": 0,
        "session_mfa_age_present": false,
        "session_mfa_age_seconds": 0
    })
}

fn internal_context_with(overrides: Value) -> Value {
    let mut base = match default_internal_context() {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    if let Value::Object(map) = overrides {
        for (key, value) in map {
            base.insert(key, value);
        }
    }
    Value::Object(base)
}

fn context_with_internal(attrs: Value, internal: Value) -> authz_types::Context {
    let mut map = match attrs {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    map.insert("_authz".to_string(), internal);
    authz_types::Context::new(Value::Object(map))
}

fn typed_internal_context_from_test_context(
    request: &authz_types::EvaluationRequest,
) -> CedarInternalContext {
    let internal = request
        .context
        .as_ref()
        .and_then(|context| context.attributes.get("_authz"))
        .cloned()
        .unwrap_or_else(default_internal_context);
    let bool_field = |key: &str| internal.get(key).and_then(Value::as_bool).unwrap_or(false);
    let integer_field = |key: &str| {
        internal
            .get(key)
            .and_then(Value::as_i64)
            .unwrap_or_default()
    };
    let string_field = |key: &str| {
        internal
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let string_list = |key: &str| {
        internal
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let entity_ref = |value: &Value| {
        let entity = value.get("__entity").expect("test entity wrapper");
        CedarEntityRef::new(
            entity
                .get("type")
                .and_then(Value::as_str)
                .expect("test entity type"),
            entity
                .get("id")
                .and_then(Value::as_str)
                .expect("test entity id"),
        )
        .expect("valid test entity ref")
    };
    let entity_list = |key: &str| {
        internal
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(&entity_ref)
            .collect()
    };
    let resource_scopes = internal
        .get("resource_scopes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|scope| CedarResourceScope {
            role: entity_ref(scope.get("role").expect("test scope role")),
            resource: entity_ref(scope.get("resource").expect("test scope resource")),
        })
        .collect();

    CedarInternalContext {
        token_present: bool_field("token_present"),
        token_valid: bool_field("token_valid"),
        token_resource_filter_enabled: bool_field("token_resource_filter_enabled"),
        token_resource_filter: entity_list("token_resource_filter"),
        resource_scopes,
        token_org_id_present: bool_field("token_org_id_present"),
        token_org_id: string_field("token_org_id"),
        token_owner_org_ids: string_list("token_owner_org_ids"),
        allowed_actions: string_list("allowed_actions"),
        session_present: bool_field("session_present"),
        session_acr: integer_field("session_acr"),
        session_amr: string_list("session_amr"),
        session_auth_age_present: bool_field("session_auth_age_present"),
        session_auth_age_seconds: integer_field("session_auth_age_seconds"),
        session_mfa_age_present: bool_field("session_mfa_age_present"),
        session_mfa_age_seconds: integer_field("session_mfa_age_seconds"),
    }
}

fn resource_scope_record(role_id: &str, resource_type: &str, resource_id: &str) -> Value {
    let entity_type = format!("Authz::{}", crate::schema::to_pascal_case(resource_type));
    serde_json::json!({
        "role": { "__entity": { "type": "Authz::Role", "id": role_id } },
        "resource": { "__entity": { "type": entity_type, "id": resource_id } }
    })
}

fn permission_actions(resource_type: &str, action_names: &[String]) -> Vec<PermissionActionRef> {
    action_names
        .iter()
        .map(|action_name| PermissionActionRef {
            resource_type: resource_type.into(),
            action_name: action_name.clone(),
        })
        .collect()
}

fn config_with_scope(scope: Scope) -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![scope],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config")
}

fn config_with_reader_writer_roles() -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
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
        permissions: vec![
            authz_types::Permission {
                id: "document:reader".into(),
                actions: permission_actions("document", &["read".into()]),
                not_actions: vec![],
                name: "Reader".into(),
                description: None,
            },
            authz_types::Permission {
                id: "document:writer".into(),
                actions: permission_actions("document", &["write".into()]),
                not_actions: vec![],
                name: "Writer".into(),
                description: None,
            },
        ],
        roles: vec![
            authz_types::Role {
                id: "reader".into(),
                name: "Reader".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:reader").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                }],
                actions: vec![],
                not_actions: vec![],
                assignment_policy: crate::bundle::permanent_assignment_policy(),
            },
            authz_types::Role {
                id: "writer".into(),
                name: "Writer".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:writer").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                }],
                actions: vec![],
                not_actions: vec![],
                assignment_policy: crate::bundle::permanent_assignment_policy(),
            },
        ],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config")
}

#[test]
fn evaluator_denies_until_implemented() {
    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };
    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation result");
    assert!(res.decision, "public read should be allowed");
}

#[test]
fn given_mutated_public_read_request_when_evaluating_then_decision_oracle_holds() {
    // Given a bundle whose only permit needs enriched properties. This is
    // the deterministic twin of the `cedar_decision` fuzz oracle: on the
    // production path, enriched requests fail before evaluation and bare
    // requests deny by default, so nothing here may ever allow.
    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };
    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let seed = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    assert!(
        evaluate_untrusted(&bundle, &seed).is_err(),
        "enriched requests must fail before evaluation on the production path"
    );
    let bare = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    assert!(
        !evaluate_untrusted(&bundle, &bare)
            .map(|response| response.decision)
            .unwrap_or(false),
        "property-less requests must never allow"
    );
    let decide = |request: &authz_types::EvaluationRequest| {
        evaluate_untrusted(&bundle, request)
            .map(|response| response.decision)
            .unwrap_or(false)
    };
    let with_subject = |subject: Subject| authz_types::EvaluationRequest {
        subject,
        ..seed.clone()
    };
    let with_resource = |resource: Resource| authz_types::EvaluationRequest {
        resource,
        ..seed.clone()
    };
    let with_action = |action: Action| authz_types::EvaluationRequest {
        action,
        ..seed.clone()
    };
    let with_context = |context: Option<authz_types::Context>| authz_types::EvaluationRequest {
        context,
        ..seed.clone()
    };
    let token_present_context = || {
        let mut internal = match default_internal_context() {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        internal.insert("token_present".to_string(), Value::Bool(true));
        context_with_internal(Value::Object(Map::new()), Value::Object(internal))
    };
    let parent_context = |key: &str| {
        let mut outer = Map::new();
        outer.insert("_authz".to_string(), default_internal_context());
        outer.insert(
            key.to_string(),
            Value::Array(vec![Value::String("Group::\"admin\"".to_string())]),
        );
        authz_types::Context::new(Value::Object(outer))
    };

    // When each mutated request reaches the evaluator.
    let mutated: Vec<(&str, authz_types::EvaluationRequest)> = vec![
        ("other user", with_subject(Subject::user("u2"))),
        ("group subject", with_subject(Subject::group("u1"))),
        ("role subject", with_subject(Subject::role("reader"))),
        (
            "private resource",
            with_resource(
                Resource::new("document", "doc1")
                    .with_properties(serde_json::json!({"is_public": false})),
            ),
        ),
        (
            "unmarked resource",
            with_resource(
                Resource::new("document", "doc1").with_properties(serde_json::json!({"other": 1})),
            ),
        ),
        ("write action", with_action(Action::new("write"))),
        ("cased action", with_action(Action::new("READ"))),
        ("empty action", with_action(Action::new(""))),
        (
            "unknown type",
            with_resource(
                Resource::new("other", "doc1")
                    .with_properties(serde_json::json!({"is_public": true})),
            ),
        ),
        ("token present", with_context(Some(token_present_context()))),
        (
            "subject parents",
            with_context(Some(parent_context("subject_parents"))),
        ),
        (
            "resource parents",
            with_context(Some(parent_context("resource_parents"))),
        ),
    ];

    // Then no mutation may allow on the production path: enriched inputs
    // fail before evaluation and bare inputs deny by default.
    for (label, request) in &mutated {
        assert!(!decide(request), "{label} must deny or fail, never allow");
    }
}

#[test]
fn untrusted_evaluation_cannot_satisfy_step_up_with_reserved_context() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "mfa".to_string())]
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
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_acr(
            "mfa",
            "Require MFA",
            AcrLevel::MultiFactor,
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            internal_context_with(serde_json::json!({
                "session_present": true,
                "session_acr": 2
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let error = evaluate_untrusted(&bundle, &request).expect_err("context must be rejected");
    assert!(
        error
            .to_string()
            .contains("trusted authorization enrichment")
    );
}

#[test]
fn evaluate_with_policy_sets_rejects_null_context_values() {
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(authz_types::Context::new(serde_json::json!({
            "_authz": default_internal_context(),
            "invalid_null": null
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let borrowed_error = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request.clone(),
        &[],
        &[],
        typed_internal_context_from_test_context(&request),
    )
    .err()
    .expect("null context should fail");
    let owned_error = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request.clone(),
        &[],
        &[],
        typed_internal_context_from_test_context(&request),
    )
    .err()
    .expect("null context should fail");
    assert!(
        borrowed_error
            .to_string()
            .contains("null values are not supported"),
        "unexpected borrowed error: {borrowed_error}",
    );
    assert!(
        owned_error
            .to_string()
            .contains("null values are not supported"),
        "unexpected owned error: {owned_error}",
    );
}

#[test]
fn evaluate_with_policy_sets_rejects_unbounded_context_values() {
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(Context::new(serde_json::json!({
            "nested": (0..=1_024).collect::<Vec<_>>()
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let error = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request.clone(),
        &[],
        &[],
        typed_internal_context_from_test_context(&request),
    )
    .err()
    .expect("unbounded context collections must be rejected");
    assert!(
        error
            .to_string()
            .contains("JSON context collection exceeds")
    );
}

#[test]
fn batch_evaluator_denies_all() {
    let batch = BatchEvaluationRequest {
        evaluations: vec![
            authz_types::EvaluationRequest {
                subject: Subject::user("u1"),
                resource: Resource::new("document", "doc1"),
                action: Action::new("read"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            authz_types::EvaluationRequest {
                subject: Subject::user("u2"),
                resource: Resource::new("document", "doc2"),
                action: Action::new("write"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
        ],
        subject_override: None,
        token_context_override: None,
    };

    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
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

    let res = evaluate_batch(&bundle, &batch).expect("batch");
    assert_eq!(2, res.evaluations.len());
    assert!(
        !res.evaluations[0].decision,
        "batch without trusted enrichment must deny"
    );
    assert!(
        !res.evaluations[1].decision,
        "write should deny without role"
    );
}

#[test]
fn evaluate_with_policy_sets_rejects_when_policy_slice_is_missing() {
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
        roles: vec![],
        scope_mappings: vec![],
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let mut bundle = compile_policy_bundle(&config, 1).expect("bundle");
    bundle
        .policy_slices
        .retain(|slice| slice.resource_type != "document");
    let error = parse_policy_sets(&bundle).expect_err("missing policy slice must be rejected");
    assert!(error.to_string().contains("policy slice manifest mismatch"));
}

#[test]
fn evaluate_with_preparsed_policy_sets_matches_standard_evaluate() {
    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
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
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let standard = evaluate_untrusted(&bundle, &request).expect("standard");
    let parsed = evaluate_with_policy_sets(&policy_sets, &request).expect("parsed");
    assert_eq!(standard.decision, parsed.decision);
    assert_eq!(standard.challenge.is_some(), parsed.challenge.is_some());
}

#[test]
fn evaluate_batch_with_preparsed_policy_sets_matches_standard_batch() {
    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
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
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");

    let batch = BatchEvaluationRequest {
        evaluations: vec![
            authz_types::EvaluationRequest {
                subject: Subject::user("u1"),
                resource: Resource::new("document", "doc1"),
                action: Action::new("read"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            authz_types::EvaluationRequest {
                subject: Subject::user("u2"),
                resource: Resource::new("document", "doc2"),
                action: Action::new("write"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
        ],
        subject_override: None,
        token_context_override: None,
    };

    let standard = evaluate_batch(&bundle, &batch).expect("standard");
    let parsed = evaluate_batch_with_policy_sets(&policy_sets, &batch).expect("parsed");
    assert_eq!(standard.evaluations.len(), parsed.evaluations.len());
    for (left, right) in standard.evaluations.iter().zip(parsed.evaluations.iter()) {
        assert_eq!(left.decision, right.decision);
        assert_eq!(left.challenge.is_some(), right.challenge.is_some());
    }
}

#[test]
fn evaluator_allows_role_membership_parent() {
    // Config: editor role permissions read+write on document (tenant scope)
    let config = authz_types::ConfigurationModel {
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
            actions: permission_actions("document", &["read".into(), "write".into()]),
            not_actions: vec![],
            name: "Editor".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "editor" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(res.decision, "role parent should allow write");
}

#[test]
fn given_mutated_role_membership_when_evaluating_trusted_path_then_role_oracle_holds() {
    // Given an editor role over document read/write. This is the
    // deterministic twin of the `cedar_role_decision` fuzz oracle: only
    // editor membership on document read/write may allow.
    let config = authz_types::ConfigurationModel {
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
            actions: permission_actions("document", &["read".into(), "write".into()]),
            not_actions: vec![],
            name: "Editor".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let parent = |parent_type: &str, parent_id: &str| EntityParentRef {
        parent_type: parent_type.to_string(),
        parent_id: parent_id.to_string(),
    };
    // Trusted-path requests carry typed internal context; the untyped
    // request `_authz` map is never trusted here. Token-absent defaults
    // satisfy the generated token guards.
    let internal = |token_present: bool| CedarInternalContext {
        token_present,
        token_valid: true,
        token_resource_filter_enabled: false,
        token_resource_filter: Vec::new(),
        resource_scopes: Vec::new(),
        token_org_id_present: false,
        token_org_id: String::new(),
        token_owner_org_ids: Vec::new(),
        allowed_actions: Vec::new(),
        session_present: false,
        session_acr: 0,
        session_amr: Vec::new(),
        session_auth_age_present: false,
        session_auth_age_seconds: 0,
        session_mfa_age_present: false,
        session_mfa_age_seconds: 0,
    };
    let decide_with_token = |subject: Subject,
                             resource: Resource,
                             action: Action,
                             parents: &[EntityParentRef],
                             token_present: bool| {
        prepare_evaluation_owned_with_trusted_parents_and_internal_context(
            authz_types::EvaluationRequest {
                subject,
                resource,
                action,
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            parents,
            &[],
            internal(token_present),
        )
        .ok()
        .and_then(|prepared| {
            evaluate_prepared_with_policy_sets(&policy_sets, prepared)
                .ok()
                .map(|response| response.decision)
        })
        .unwrap_or(false)
    };
    let decide =
        |subject: Subject, resource: Resource, action: Action, parents: &[EntityParentRef]| {
            decide_with_token(subject, resource, action, parents, false)
        };

    // The seed conferring membership must allow both gated actions.
    assert!(
        decide(
            Subject::user("u1"),
            Resource::new("document", "doc1"),
            Action::new("read"),
            &[parent("role", "editor")],
        ),
        "editor membership must allow read"
    );

    // When membership, action, or resource is mutated.
    let mutated: Vec<(&str, bool)> = vec![
        (
            "unknown role",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[parent("role", "viewer")],
            ),
        ),
        (
            "group-typed membership",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[parent("group", "editor")],
            ),
        ),
        (
            "empty role id",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[parent("role", "")],
            ),
        ),
        (
            "no membership",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[],
            ),
        ),
        (
            "ungated action",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("delete"),
                &[parent("role", "editor")],
            ),
        ),
        (
            "cased action",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("WRITE"),
                &[parent("role", "editor")],
            ),
        ),
        (
            "unknown resource type",
            decide(
                Subject::user("u1"),
                Resource::new("other", "doc1"),
                Action::new("write"),
                &[parent("role", "editor")],
            ),
        ),
        (
            "duplicate membership",
            decide(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[parent("role", "editor"), parent("role", "editor")],
            ),
        ),
        (
            "token present without validity",
            decide_with_token(
                Subject::user("u1"),
                Resource::new("document", "doc1"),
                Action::new("write"),
                &[parent("role", "editor")],
                true,
            ),
        ),
    ];

    // Then only true editor membership on gated actions allows; duplicates
    // of the same membership keep the allow while every other mutation
    // denies or fails.
    for (label, decision) in mutated {
        if label == "duplicate membership" {
            assert!(decision, "{label} must preserve the seed allow");
        } else {
            assert!(!decision, "{label} must deny or fail, never allow");
        }
    }
}

#[test]
fn untrusted_context_cannot_inject_role_membership_parent() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "editor" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let error = evaluate_untrusted(&bundle, &request).expect_err("context must be rejected");
    assert!(
        error
            .to_string()
            .contains("trusted authorization enrichment")
    );
}

#[test]
fn evaluator_denies_when_token_filter_excludes_resource() {
    let config = authz_types::ConfigurationModel {
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_resource_filter_enabled": true,
        "token_resource_filter": [
            { "__entity": { "type": "Authz::Document", "id": "doc-allowed" } }
        ],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc-blocked"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "token filter should deny");
}

#[test]
fn evaluator_denies_when_step_up_missing_session() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "mfa".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = authz_types::ConfigurationModel {
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
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
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "step-up guard should deny without session");
}

#[test]
fn evaluator_denies_public_read_without_token_permission() {
    let config = authz_types::ConfigurationModel {
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
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };
    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(Value::Object(Map::new()), internal)),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "token ceiling should deny public read");
}

#[test]
fn evaluator_allows_org_scope_when_org_matches() {
    let config = config_with_scope(Scope::Org);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"org_id": "org1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(res.decision, "org scope should allow when org matches");
}

#[test]
fn evaluator_denies_org_scope_when_org_mismatched() {
    let config = config_with_scope(Scope::Org);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"org_id": "org1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org2"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "org scope should deny when org mismatched");
}

#[test]
fn evaluator_allows_group_scope_when_group_matches() {
    let config = config_with_scope(Scope::Group);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"group_id": "g1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"group_id": "g1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(res.decision, "group scope should allow when group matches");
}

#[test]
fn evaluator_allows_own_scope_when_owner_matches() {
    let config = config_with_scope(Scope::Own);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"id": "u1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"owner_id": "u1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(res.decision, "own scope should allow when owner matches");
}

#[test]
fn evaluator_allows_shared_scope_when_user_is_shared() {
    let config = config_with_scope(Scope::Shared);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"id": "u1"})),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "shared_with": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "shared scope should allow when user is in shared_with"
    );
}

#[test]
fn evaluator_allows_resource_scope_when_resource_matches() {
    let config = config_with_scope(Scope::resource("document"));
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "resource_scopes": [resource_scope_record("reader", "document", "doc1")]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "resource scope should allow when resource matches"
    );
}

#[test]
fn evaluator_denies_resource_scope_when_resource_not_scoped() {
    let config = config_with_scope(Scope::resource("document"));
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "resource_scopes": [resource_scope_record("reader", "document", "doc1")]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc2"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "resource scope should deny when resource is not scoped"
    );
}

#[test]
fn evaluator_allows_org_relationship_scope() {
    let config = config_with_scope(Scope::OrgRelationship);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "org_parents": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "org relationship scope should allow when principal is in org_parents"
    );
}

#[test]
fn evaluator_allows_group_relationship_scope() {
    let config = config_with_scope(Scope::GroupRelationship);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "group_parents": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "group relationship scope should allow when principal is in group_parents"
    );
}

#[test]
fn evaluator_denies_when_token_org_guard_missing_resource_org_id() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_org_id_present": true,
        "token_org_id": "org1",
        "token_owner_org_ids": ["org1"],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "token org guard should deny without resource org_id"
    );
}

#[test]
fn evaluator_allows_when_token_org_guard_matches() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_org_id_present": true,
        "token_org_id": "org1",
        "token_owner_org_ids": ["org1"],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "token org guard should allow when org matches"
    );
}

#[test]
fn evaluator_denies_when_token_action_not_allowed_even_with_role() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "token action list should deny when action is not permitted"
    );
}

#[test]
fn evaluator_denies_recent_auth_when_auth_age_too_old() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "recent".to_string())]
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
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 1,
        "session_auth_age_present": true,
        "session_auth_age_seconds": 900
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "recent auth rule should deny when auth age exceeds max"
    );
}

#[test]
fn evaluator_allows_recent_auth_when_auth_age_within_limit() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "recent".to_string())]
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
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 1,
        "session_auth_age_present": true,
        "session_auth_age_seconds": 120
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "recent auth rule should allow when auth age within max"
    );
}

#[test]
fn evaluator_denies_when_mfa_age_missing() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("mfa_age".to_string()),
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule {
            rule_id: "mfa_age".into(),
            name: "MFA Age".into(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: Some(120),
            required_amr: Vec::new(),
            applies_to_api_keys: true,
        }],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_mfa_age_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "MFA age rule should deny when mfa age missing"
    );
}

#[test]
fn evaluator_allows_when_mfa_age_within_limit() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("mfa_age".to_string()),
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule {
            rule_id: "mfa_age".into(),
            name: "MFA Age".into(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: Some(120),
            required_amr: Vec::new(),
            applies_to_api_keys: true,
        }],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_mfa_age_present": true,
        "session_mfa_age_seconds": 30
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(res.decision, "MFA age rule should allow when within limit");
}

#[test]
fn evaluator_denies_when_required_amr_missing() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("amr".to_string()),
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_amr(
            "amr",
            "Require AMR",
            vec!["webauthn".into(), "otp".into()],
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_amr": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "AMR rule should deny when no required amr present"
    );
}

#[test]
fn evaluator_allows_when_required_amr_present() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("amr".to_string()),
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_amr(
            "amr",
            "Require AMR",
            vec!["webauthn".into(), "otp".into()],
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_amr": ["otp"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "AMR rule should allow when required amr present"
    );
}

#[test]
fn evaluator_allows_step_up_with_token_when_api_keys_exempt() {
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": ["document:read"],
        "session_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "step-up should allow token when api keys are exempt"
    );
}

#[test]
fn evaluator_denies_when_subject_has_wrong_linked_role() {
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
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
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
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "writer" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "wrong linked role must not authorize");
}

#[test]
fn evaluator_keeps_allowed_actions_action_specific() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "writer" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": true,
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "read allowance must not leak into write");
}

#[test]
fn evaluator_denies_when_token_invalid_even_if_link_matches() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": false,
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "invalid token must fail closed");
}

#[test]
fn evaluator_denies_when_token_org_mismatches_resource_org() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org-b"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": true,
                "token_org_id_present": true,
                "token_org_id": "org-a",
                "token_owner_org_ids": ["org-a"],
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "foreign org resource must be denied");
}

#[test]
fn evaluator_forbid_link_overrides_matching_permit_link() {
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
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![],
            actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
                limit: None,
            }],
            not_actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
                limit: None,
            }],
            assignment_policy: crate::bundle::permanent_assignment_policy(),
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate_with_test_trust(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "forbid should override matching permit");
}

#[test]
fn evaluator_keeps_public_read_separate_from_role_policies() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    let public_read = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let protected_write = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let public_read_res = evaluate_with_test_trust(&bundle, &public_read).expect("public read");
    let protected_write_res =
        evaluate_with_test_trust(&bundle, &protected_write).expect("protected write");
    assert!(public_read_res.decision, "public read should stay static");
    assert!(
        !protected_write_res.decision,
        "write should still require a matching role link"
    );
}

#[test]
fn untrusted_evaluation_rejects_caller_owned_resource_properties() {
    let config = config_with_scope(Scope::Public);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("attacker"),
        resource: Resource::new("document", "secret")
            .with_properties(serde_json::json!({ "is_public": true })),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let error = evaluate_untrusted(&bundle, &request)
        .expect_err("caller-owned resource properties must not reach Cedar");
    assert!(
        error
            .to_string()
            .contains("trusted authorization enrichment"),
        "unexpected error: {error}"
    );
}

#[test]
fn given_external_request_with_authorization_properties_when_using_policy_sets_then_rejects() {
    // Given parsed policies and a wire request that tries to supply a resource
    // authorization property directly.
    let config = config_with_scope(Scope::Public);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("attacker"),
        resource: Resource::new("document", "secret")
            .with_properties(serde_json::json!({ "is_public": true })),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    // When both public parsed-policy entrypoints evaluate the external request.
    let borrowed = evaluate_with_policy_sets(&policy_sets, &request)
        .expect_err("borrowed entrypoint must reject caller-owned properties");
    let owned = evaluate_owned_with_policy_sets(&policy_sets, request)
        .expect_err("owned entrypoint must reject caller-owned properties");

    // Then the single preparation boundary rejects the forged authorization
    // state for both ownership modes.
    for error in [borrowed, owned] {
        assert!(
            error
                .to_string()
                .contains("trusted authorization enrichment"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn untrusted_evaluation_rejects_caller_owned_context() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("attacker"),
        resource: Resource::new("document", "secret"),
        action: Action::new("read"),
        context: Some(Context::new(serde_json::json!({
            "is_admin": true,
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let error = evaluate_untrusted(&bundle, &request)
        .expect_err("caller-owned context must not reach Cedar");
    assert!(
        error
            .to_string()
            .contains("trusted authorization enrichment"),
        "unexpected error: {error}"
    );
}

#[test]
fn untrusted_batch_rejects_caller_owned_security_fields() {
    let config = config_with_scope(Scope::Public);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = BatchEvaluationRequest {
        evaluations: vec![authz_types::EvaluationRequest {
            subject: Subject::user("attacker"),
            resource: Resource::new("document", "secret")
                .with_properties(serde_json::json!({ "is_public": true })),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        }],
        subject_override: None,
        token_context_override: None,
    };

    let error = evaluate_batch(&bundle, &request)
        .expect_err("batch caller-owned security fields must be rejected");
    assert!(
        error
            .to_string()
            .contains("trusted authorization enrichment"),
        "unexpected error: {error}"
    );
}

#[test]
fn typed_internal_preparation_drops_wire_owned_generic_context() {
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("user-1"),
        resource: Resource::new("document", "secret"),
        action: Action::new("read"),
        context: Some(Context::new(serde_json::json!({
            "is_admin": true,
            "request_region": "attacker-controlled",
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request.clone(),
        &[],
        &[],
        typed_internal_context_from_test_context(&request),
    )
    .expect("typed preparation");
    let context = prepared.context();

    assert!(context.and_then(|value| value.get("is_admin")).is_none());
    assert!(
        context
            .and_then(|value| value.get("request_region"))
            .is_none()
    );
    assert!(context.and_then(|value| value.get("_authz")).is_some());
}

#[test]
fn diagnostics_retain_determining_policy_and_evaluation_error_categories() {
    use std::str::FromStr;

    use cedar_policy::PolicySet;

    let policies = PolicySet::from_str(
        r#"
        @id("allow_read") permit(principal, action, resource);
        @id("error_read") permit(principal, action, resource)
            when { resource.missing_attribute == "value" };
        "#,
    )
    .expect("policies");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let prepared = crate::prepare_evaluation_owned(request).expect("prepared request");
    let result =
        crate::evaluation::evaluate_prepared_with_policy_set_diagnostics(&policies, &prepared);

    assert!(
        !result.response.decision,
        "a policy evaluation error must fail closed even when Cedar reports allow"
    );
    assert_eq!(result.determining_policy_ids.len(), 1);
    assert!(!result.determining_policy_ids[0].is_empty());
    assert_eq!(
        result.evaluation_errors,
        [crate::CedarEvaluationErrorCategory::AttributeMissing]
    );
}

#[test]
fn error_diagnostics_skip_policy_ids_on_healthy_allow_and_deny() {
    use std::str::FromStr;

    use cedar_policy::PolicySet;

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    for (policy, expected_decision) in [
        (r#"@id("allow") permit(principal, action, resource);"#, true),
        (r#"@id("deny") forbid(principal, action, resource);"#, false),
    ] {
        let policies = PolicySet::from_str(policy).expect("healthy policy");
        let prepared = crate::prepare_evaluation_owned(request.clone()).expect("prepared request");
        let result = crate::evaluation::evaluate_prepared_with_policy_set_error_diagnostics(
            &policies, &prepared,
        );
        assert_eq!(result.response.decision, expected_decision);
        assert_eq!(result.determining_policy_count, 0);
        assert!(result.evaluation_errors.is_empty());
    }
}

#[test]
fn error_diagnostics_preserve_missing_entity_and_attribute_categories() {
    use std::str::FromStr;

    use cedar_policy::PolicySet;

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    for (policy, expected_error) in [
        (
            r#"permit(principal, action, resource) when { Team::"missing".active };"#,
            crate::CedarEvaluationErrorCategory::EntityMissing,
        ),
        (
            r#"permit(principal, action, resource) when { resource.missing_attribute == "value" };"#,
            crate::CedarEvaluationErrorCategory::AttributeMissing,
        ),
    ] {
        let policies = PolicySet::from_str(policy).expect("error policy");
        let prepared = crate::prepare_evaluation_owned(request.clone()).expect("prepared request");
        let result = crate::evaluation::evaluate_prepared_with_policy_set_error_diagnostics(
            &policies, &prepared,
        );
        assert!(!result.response.decision);
        assert_eq!(result.determining_policy_count, 0);
        assert_eq!(result.evaluation_errors, [expected_error]);
    }
}

#[test]
fn given_prepared_registry_when_preparing_actions_then_unknown_entries_fail_closed() {
    // Given a registry prepared from the current resource/action configuration.
    let registry =
        CedarUidRegistry::new(&config_with_scope(Scope::Tenant)).expect("registry should prepare");

    // When callers request one known and two unknown actions.
    let known = registry.prepare_action("document", "read");
    let unknown_resource = registry.prepare_action("missing", "read");
    let unknown_action = registry.prepare_action("document", "write");

    // Then only the configured action is accepted.
    assert!(known.is_ok());
    assert!(unknown_resource.is_err());
    assert!(unknown_action.is_err());
}

#[test]
fn given_evaluation_error_categories_when_rendering_then_wire_names_remain_stable() {
    // Given every Cedar error category exposed by the diagnostics contract.
    let categories = [
        (
            crate::CedarEvaluationErrorCategory::EntityMissing,
            "entity_missing",
        ),
        (
            crate::CedarEvaluationErrorCategory::AttributeMissing,
            "attribute_missing",
        ),
        (
            crate::CedarEvaluationErrorCategory::ExtensionLookup,
            "extension_lookup",
        ),
        (crate::CedarEvaluationErrorCategory::Type, "type"),
        (
            crate::CedarEvaluationErrorCategory::ExtensionArgumentCount,
            "extension_argument_count",
        ),
        (
            crate::CedarEvaluationErrorCategory::IntegerOverflow,
            "integer_overflow",
        ),
        (
            crate::CedarEvaluationErrorCategory::UnlinkedSlot,
            "unlinked_slot",
        ),
        (
            crate::CedarEvaluationErrorCategory::ExtensionExecution,
            "extension_execution",
        ),
        (crate::CedarEvaluationErrorCategory::NonValue, "non_value"),
        (
            crate::CedarEvaluationErrorCategory::RecursionLimit,
            "recursion_limit",
        ),
    ];

    // When each category is rendered for an external diagnostics response.
    for (category, expected) in categories {
        // Then its stable machine-readable name is preserved.
        assert_eq!(category.as_str(), expected);
    }
}

#[test]
fn given_owned_evaluation_request_when_evaluating_single_and_batch_then_decisions_match() {
    // Given one parsed policy set and a caller-owned request without
    // enrichment.
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    // When the same request uses both owned evaluation entrypoints.
    let single =
        evaluate_owned_with_policy_sets(&policy_sets, request.clone()).expect("single evaluation");
    let batch = evaluate_batch_owned_with_policy_sets(
        &policy_sets,
        BatchEvaluationRequest {
            evaluations: vec![request],
            subject_override: None,
            token_context_override: None,
        },
    )
    .expect("batch evaluation");

    // Then both owned paths fail closed for the un-enriched tenant request.
    assert_eq!(batch.evaluations.len(), 1);
    assert!(
        !single.decision,
        "an un-enriched tenant request must be denied"
    );
    assert!(
        !batch.evaluations[0].decision,
        "an un-enriched tenant batch request must be denied"
    );
    assert_eq!(single.decision, batch.evaluations[0].decision);
}

#[test]
fn given_oversized_batch_when_evaluating_then_rejects_before_policy_access() {
    // Given a tampered bundle and more requests than the bounded batch contract
    // allows.
    let config = config_with_scope(Scope::Tenant);
    let mut bundle = compile_policy_bundle(&config, 1).expect("bundle");
    bundle.manifest.config_fingerprint = None;
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let batch = BatchEvaluationRequest {
        evaluations: vec![request; authz_types::MAX_BATCH_EVALUATIONS + 1],
        subject_override: None,
        token_context_override: None,
    };

    // When the oversized batch is evaluated through the bundle entrypoint.
    let error = evaluate_batch(&bundle, &batch).expect_err("oversized batch must be rejected");

    // Then the batch limit wins before the invalid bundle reaches policy
    // parsing.
    assert_eq!(
        error,
        crate::CedarError::evaluation(format!(
            "batch exceeds maximum of {} evaluations",
            authz_types::MAX_BATCH_EVALUATIONS
        ))
    );
}

#[test]
fn given_registry_when_request_uses_unprepared_subject_resource_or_action_then_rejects() {
    // Given a registry that only prepares user/document/read.
    let registry =
        CedarUidRegistry::new(&config_with_scope(Scope::Tenant)).expect("registry should prepare");
    let mut request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    // When each request selects an unprepared registry dimension.
    request.subject.subject_type = authz_types::SubjectType::Custom("device".into());
    assert!(registry.request_uids(&request).is_err());
    request.subject = Subject::user("u1");
    request.resource = Resource::new("missing", "doc1");
    assert!(registry.request_uids(&request).is_err());
    request.resource = Resource::new("document", "doc1");
    request.action = Action::new("write");
    assert!(registry.request_uids(&request).is_err());

    // Then none of the unprepared identifiers can cross the registry boundary.
}

#[test]
fn given_untrusted_json_limits_when_preparing_then_rejects_depth_size_numeric_and_entity_escapes() {
    // Given malformed or oversized values at each supported Cedar conversion
    // boundary.
    let mut deeply_nested = Value::Bool(true);
    for _ in 0..17 {
        deeply_nested = Value::Array(vec![deeply_nested]);
    }
    let mut oversized_object = serde_json::Map::new();
    for index in 0..=1_024 {
        oversized_object.insert(format!("field_{index}"), Value::Bool(true));
    }
    let cases = [
        (
            "depth",
            deeply_nested,
            "JSON context nesting exceeds maximum",
        ),
        (
            "string",
            Value::String("x".repeat(64 * 1024 + 1)),
            "JSON context string exceeds maximum",
        ),
        (
            "object",
            Value::Object(oversized_object),
            "JSON context object exceeds maximum",
        ),
        (
            "numeric",
            Value::Number(serde_json::Number::from(u64::MAX)),
            "unsupported numeric value",
        ),
        (
            "entity",
            serde_json::json!({
                "__entity": { "type": "Authz::Role", "id": "reader" },
                "extra": true
            }),
            "entity escape object must only contain __entity",
        ),
    ];

    // When trusted preparation validates caller-owned generic context before
    // discarding it.
    for (label, value, expected) in cases {
        let request = authz_types::EvaluationRequest {
            subject: Subject::user("u1"),
            resource: Resource::new("document", "doc1"),
            action: Action::new("read"),
            context: Some(Context::new(serde_json::json!({ "candidate": value }))),
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let error = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
            request.clone(),
            &[],
            &[],
            typed_internal_context_from_test_context(&request),
        )
        .err()
        .expect("invalid generic context must fail closed");

        // Then the specific guard explains the rejection.
        assert!(
            error.to_string().contains(expected),
            "{label} case returned unexpected error: {error}"
        );
    }
}

#[test]
fn given_compiled_bundle_when_validating_against_config_then_accepts_and_rejects_fingerprint_tampering()
 {
    // Given a bundle compiled from the exact runtime configuration.
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    // When the intact bundle is checked and its fingerprint is then tampered
    // with.
    validate_bundle_for_config(&config, &bundle).expect("matching bundle should validate");
    let mut tampered = bundle;
    tampered.manifest.config_fingerprint = Some("0".repeat(64));
    let error = validate_bundle_for_config(&config, &tampered)
        .expect_err("bundle from another configuration must be rejected");

    // Then configuration binding fails before Cedar can evaluate the payload.
    assert!(error.to_string().contains("configuration fingerprint"));
}

#[test]
fn given_trusted_values_when_policy_reads_them_then_all_converted_inputs_allow() {
    // Given trusted enrichment with nested records, sets, an entity escape,
    // resource attributes, context, and both subject/resource ancestry.
    use cedar_policy::PolicySet;

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({
            "profile": {"age": 42, "labels": ["staff", "reviewer"]},
            "role_ref": {"__entity": {"type": "Authz::Role", "id": "reader"}}
        })),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "owner_id": "u1",
            "metadata": {"region": "eu-west-1"}
        })),
        action: Action::new("read"),
        context: Some(Context::new(serde_json::json!({"risk_score": 7}))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_parents = [EntityParentRef {
        parent_type: "role".into(),
        parent_id: "reader".into(),
    }];
    let resource_parents = [EntityParentRef {
        parent_type: "org".into(),
        parent_id: "tenant-1".into(),
    }];
    let policy = PolicySet::from_str(
        r#"
        @id("all_trusted_values") permit(principal, action, resource)
            when {
                principal in Authz::Role::"reader" &&
                resource in Authz::Org::"tenant-1" &&
                principal has profile &&
                principal.profile.age == 42 &&
                principal.profile.labels.contains("staff") &&
                principal.profile.labels.contains("reviewer") &&
                principal has role_ref &&
                principal.role_ref == Authz::Role::"reader" &&
                resource has owner_id &&
                resource.owner_id == principal.id &&
                resource has metadata &&
                resource.metadata.region == "eu-west-1" &&
                context has risk_score &&
                context.risk_score == 7
            };
        "#,
    )
    .expect("policy should consume every converted value");

    // When Cedar evaluates the prepared trusted request from the outside.
    let prepared = prepare_evaluation_owned_with_trusted_parents(
        request.clone(),
        &subject_parents,
        &resource_parents,
    )
    .expect("trusted values should prepare");
    let allowed =
        crate::evaluation::evaluate_prepared_with_policy_set_diagnostics(&policy, &prepared);

    // Then the policy can observe every converted property and ancestry edge.
    assert!(allowed.response.decision, "all trusted values should allow");
    assert!(allowed.evaluation_errors.is_empty());

    // When one consumed nested value is mutated before preparation.
    let mut denied_request = request.clone();
    denied_request.resource.properties = Some(serde_json::json!({
        "owner_id": "u1",
        "metadata": {"region": "us-east-1"}
    }));
    let prepared_denied = prepare_evaluation_owned_with_trusted_parents(
        denied_request,
        &subject_parents,
        &resource_parents,
    )
    .expect("mutated trusted values should still prepare");
    let denied =
        crate::evaluation::evaluate_prepared_with_policy_set_diagnostics(&policy, &prepared_denied);

    // Then the negative mutation is denied by policy rather than ignored.
    assert!(!denied.response.decision, "mutated resource must be denied");
    assert!(denied.evaluation_errors.is_empty());
}

#[test]
fn given_trusted_preparation_when_parent_type_is_invalid_then_rejects_before_entity_build() {
    // Given a trusted parent with a Cedar-invalid entity type.
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let parent = EntityParentRef {
        parent_type: ":".into(),
        parent_id: "reader".into(),
    };

    // When trusted preparation converts that relationship.
    let error = match prepare_evaluation_owned_with_trusted_parents(request, &[parent], &[]) {
        Ok(_) => panic!("invalid parent entity types must fail closed"),
        Err(error) => error,
    };

    // Then no malformed parent can reach Cedar evaluation.
    assert!(error.to_string().contains("Cedar entity type is invalid"));
}

#[test]
fn given_trusted_parent_evaluation_when_using_owned_entrypoint_then_it_fails_closed_without_policy_context()
 {
    // Given a real compiled policy and a trusted role parent, but no typed
    // internal token context (the entrypoint intentionally accepts parents
    // only).
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    // When the parent-aware owned evaluator is called.
    let response = evaluate_owned_with_trusted_parents_and_policy_sets(
        &policy_sets,
        request,
        &[EntityParentRef {
            parent_type: "role".into(),
            parent_id: "reader".into(),
        }],
        &[],
    )
    .expect("policy evaluation should return a decision");

    // Then the generated token guard denies rather than treating absent
    // internal authorization context as proof of access.
    assert!(!response.decision);
}

#[test]
fn given_frame_for_resource_without_policy_slice_when_evaluating_then_returns_structured_denial() {
    // Given a valid bundle whose policy metadata names a different resource.
    let config = config_with_scope(Scope::Tenant);
    let mut bundle = compile_policy_bundle(&config, 1).expect("bundle");
    for (slice, meta) in bundle
        .policy_slices
        .iter_mut()
        .zip(bundle.manifest.policy_slices.iter_mut())
    {
        slice.resource_type = "other_resource".into();
        meta.key = "other_resource".into();
    }
    let policy_sets = parse_policy_sets(&bundle).expect("self-consistent policy metadata");
    let registry = CedarUidRegistry::new(&config).expect("registry");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let frame = prepare_batch_frame_owned_with_registry_and_trusted_internal_context(
        &registry,
        request,
        &[],
        &[],
        typed_internal_context_from_test_context(&authz_types::EvaluationRequest {
            subject: Subject::user("u1"),
            resource: Resource::new("document", "doc1"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        }),
    )
    .expect("frame");
    let action = registry.prepare_action("document", "read").expect("action");

    // When the frame is evaluated against that bundle.
    let diagnostics = evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
        &policy_sets,
        &frame,
        &action,
    )
    .expect("missing policy slice is a deny response");

    // Then callers receive a deterministic, structured denial.
    assert!(!diagnostics.response.decision);
    assert_eq!(diagnostics.determining_policy_count, 0);
    assert!(diagnostics.evaluation_errors.is_empty());
    assert!(
        diagnostics
            .response
            .context
            .as_ref()
            .and_then(|context| context.reason.as_deref())
            .is_some_and(|reason| reason.contains("policy slice not found"))
    );
}

#[test]
fn given_malformed_entity_escape_when_trusted_preparation_converts_then_rejects_shape() {
    // Given each malformed shape accepted by the JSON parser but not by the
    // Cedar entity escape contract.
    let cases = [
        (
            serde_json::json!({"role_ref": {"__entity": true}}),
            "__entity must be an object",
        ),
        (
            serde_json::json!({"role_ref": {"__entity": {"id": "reader"}}}),
            "__entity.type must be a string",
        ),
        (
            serde_json::json!({
                "role_ref": {"__entity": {"type": "Authz::Role"}}
            }),
            "__entity.id must be a string",
        ),
    ];

    // When each shape crosses the trusted entity conversion boundary.
    for (value, expected) in cases {
        let request = authz_types::EvaluationRequest {
            subject: Subject::user("u1").with_properties(value),
            resource: Resource::new("document", "doc1"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let error = match prepare_evaluation_owned_with_trusted_parents(request, &[], &[]) {
            Ok(_) => panic!("malformed entity escapes must fail closed"),
            Err(error) => error,
        };

        // Then the shape-specific diagnostic remains recoverable and explicit.
        assert!(error.to_string().contains(expected));
    }
}

#[test]
fn given_schema_payloads_over_aggregate_limit_when_validating_then_rejects_before_manifest_parsing()
{
    // Given individually bounded schema slices whose aggregate exceeds the
    // bundle ceiling.
    let schema = "x".repeat(crate::bundle::SLICE_SOFT_MAX_BYTES);
    let count = crate::bundle::BUNDLE_SCHEMA_MAX_BYTES / schema.len() + 1;
    let schema_slices = (0..count)
        .map(|index| SchemaSlice {
            resource_type: format!("resource_{index}"),
            schema_json: schema.clone(),
            size_bytes: schema.len(),
        })
        .collect();
    let bundle = CompiledBundle {
        base_schema_json: String::new(),
        schema_slices,
        policy_slices: Vec::<PolicySlice>::new(),
        manifest: BundleManifest {
            version: 1,
            config_fingerprint: None,
            base_schema_sha256: None,
            schema_slices: Vec::<SliceMeta>::new(),
            policy_slices: Vec::<SliceMeta>::new(),
            compiled_at_ms: None,
        },
        version: 1,
    };

    // When the integrity boundary validates the bundle.
    let error =
        validate_bundle_integrity(&bundle).expect_err("aggregate schema size must be bounded");

    // Then oversized aggregate input is rejected before any digest or Cedar
    // parse.
    assert!(
        error
            .to_string()
            .contains("schema bundle exceeds size limit")
    );
}

#[test]
fn given_cedar_extension_and_arithmetic_errors_when_diagnosing_then_fails_closed_with_category() {
    // Given policies that reach distinct Cedar evaluator error categories.
    use cedar_policy::PolicySet;

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let cases = [
        (
            r#"permit(principal, action, resource) when { ip(1).isIpv4() };"#,
            crate::CedarEvaluationErrorCategory::Type,
        ),
        (
            r#"permit(principal, action, resource) when { 9223372036854775807 + 1 > 0 };"#,
            crate::CedarEvaluationErrorCategory::IntegerOverflow,
        ),
        (
            r#"permit(principal, action, resource) when { ip("not-an-ip").isIpv4() };"#,
            crate::CedarEvaluationErrorCategory::ExtensionExecution,
        ),
        (
            r#"permit(principal, action, resource) when { ip("127.0.0.1", "extra").isIpv4() };"#,
            crate::CedarEvaluationErrorCategory::ExtensionArgumentCount,
        ),
    ];

    // When each policy is evaluated through the diagnostics boundary.
    for (policy, expected_category) in cases {
        let policies = PolicySet::from_str(policy).expect("policy should parse");
        let prepared = crate::prepare_evaluation_owned(request.clone()).expect("prepared request");
        let diagnostics = crate::evaluation::evaluate_prepared_with_policy_set_error_diagnostics(
            &policies, &prepared,
        );

        // Then an evaluator failure is denied and classified for operators.
        assert!(!diagnostics.response.decision);
        assert_eq!(diagnostics.evaluation_errors, [expected_category]);
    }
}
