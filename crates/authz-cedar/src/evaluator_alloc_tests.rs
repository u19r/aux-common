use std::{collections::HashMap, hint::black_box};

use alloc_counter::AllocationGuard;
use authz_types::{
    Action, ConfigurationModel, EvaluationRequest, PermissionActionRef, PermissionId, Resource,
    Scope, Subject,
};
use serde_json::Value;

use crate::{compile_policy_bundle, evaluate_with_policy_sets, parse_policy_sets};

const ITERATIONS: usize = 512;
const MAX_ALLOCATIONS_PER_RUN: u64 = 1_050_000;
const MAX_ALLOCATED_BYTES_PER_RUN: u64 = 320_000_000;
const STRICT_ALLOC_GUARD_ENV: &str = "AUXFN_ENFORCE_ALLOC_GUARDS";

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
        subject: Subject::user("u1")
            .with_properties(serde_json::json!({ "display_name": "user one" })),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({ "owner_id": "u1" })),
        action: Action::new("read"),
        context: Some(authz_types::Context::new(serde_json::json!({
            "_authz": default_internal_context(),
            "subject_parents": [{ "type": "role", "id": "reader" }],
            "resource_parents": [{ "type": "collection", "id": "col-1" }]
        }))),
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

#[test]
fn evaluate_with_policy_sets_direct_path_budget_tests() {
    // Baseline snapshot (2026-03-24, template-linked policy payloads,
    // ITERATIONS=512): direct_path: 965,457 allocs, 297,774,768 bytes
    let (policy_sets, request) = allocation_fixture();
    let report = measure_direct_path(&policy_sets, &request);

    alloc_counter::emit_report(&report);

    if std::env::var(STRICT_ALLOC_GUARD_ENV).ok().as_deref() != Some("1") {
        eprintln!(
            "allocation regression guard skipped; set {}=1 for a dedicated single-threaded run",
            STRICT_ALLOC_GUARD_ENV
        );
        return;
    }

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
}
