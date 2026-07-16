use std::{collections::{HashMap, HashSet}, hint::black_box, time::Instant};

use alloc_counter::AllocationGuard;
use authz_types::{
    Action, ConfigurationModel, Context, EvaluationRequest, FineGrainedScopes, JwtContext,
    PermissionActionRef, PermissionId, Resource, ResourceSelection, RoleAssignment, RoleScope,
    Scope, ScopeMappingEntry, Subject, TokenContext, TokenScopeConfig,
};
use chrono::{TimeZone, Utc};
use serde_json::json;

use crate::{
    ActionPolicyDecision, EffectiveRoleAssignment, EvaluationRuntime, LocalAuthzEvaluator,
    LocalEvaluationInput, ParentRef, ResourceAccessSnapshot, SubjectAccessSnapshot,
    action_policy_decision_bits, build_subject_parent_template, enrich_request_with_snapshots,
    permissions_for_request_bits,
};
use crate::local_evaluator::inject_internal_context;

fn prepare_legacy_internal_context(
    runtime: &EvaluationRuntime,
    input: &LocalEvaluationInput,
    now: chrono::DateTime<Utc>,
) -> authz_cedar::PreparedCedarEvaluation {
    let assignments = input.subject_access.active_assignments_at(now);
    let scoped = permissions_for_request_bits(
        runtime,
        &assignments,
        &input.request,
        &input.request.subject,
    );
    let internal = crate::local_evaluator::build_internal_context_at(
        runtime,
        &input.request,
        &scoped.permissions,
        input.request.token_context.as_ref(),
        &assignments,
        input.request.session_context.as_ref(),
        now,
    );
    let mut enriched = enrich_request_with_snapshots(
        &input.tenant_id,
        input.request.clone(),
        &input.subject_access,
        &input.resource_access,
    )
    .expect("legacy enrichment");
    inject_internal_context(&mut enriched.request, internal);
    let subject_parents = enriched
        .subject_parents
        .iter()
        .map(|parent| authz_cedar::EntityParentRef {
            parent_type: parent.ref_type.clone(),
            parent_id: parent.id.clone(),
        })
        .collect::<Vec<_>>();
    let resource_parents = enriched
        .resource_parents
        .iter()
        .map(|parent| authz_cedar::EntityParentRef {
            parent_type: parent.ref_type.clone(),
            parent_id: parent.id.clone(),
        })
        .collect::<Vec<_>>();
    authz_cedar::prepare_evaluation_owned_with_parents(
        enriched.request,
        &subject_parents,
        &resource_parents,
    )
    .expect("legacy preparation")
}

fn prepare_typed_internal_context(
    runtime: &EvaluationRuntime,
    input: &LocalEvaluationInput,
    now: chrono::DateTime<Utc>,
) -> authz_cedar::PreparedCedarEvaluation {
    let assignments = input.subject_access.active_assignments_at(now);
    let scoped = permissions_for_request_bits(
        runtime,
        &assignments,
        &input.request,
        &input.request.subject,
    );
    let internal = crate::local_evaluator::build_cedar_internal_context_at(
        runtime,
        &input.request,
        &scoped.permissions,
        input.request.token_context.as_ref(),
        &assignments,
        input.request.session_context.as_ref(),
        now,
    )
    .expect("typed internal context");
    let enriched = enrich_request_with_snapshots(
        &input.tenant_id,
        input.request.clone(),
        &input.subject_access,
        &input.resource_access,
    )
    .expect("typed enrichment");
    let subject_parents = enriched
        .subject_parents
        .iter()
        .map(|parent| authz_cedar::EntityParentRef {
            parent_type: parent.ref_type.clone(),
            parent_id: parent.id.clone(),
        })
        .collect::<Vec<_>>();
    let resource_parents = enriched
        .resource_parents
        .iter()
        .map(|parent| authz_cedar::EntityParentRef {
            parent_type: parent.ref_type.clone(),
            parent_id: parent.id.clone(),
        })
        .collect::<Vec<_>>();
    authz_cedar::prepare_evaluation_owned_with_registry_and_internal_context(
        runtime.cedar_uids(),
        enriched.request,
        &subject_parents,
        &resource_parents,
        internal,
    )
    .expect("typed preparation")
}

#[test]
fn cedar_diagnostics_log_only_allowlisted_metadata() {
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct TestWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for TestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("test log lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer_buffer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || TestWriter(Arc::clone(&writer_buffer)))
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        crate::local_evaluator::record_cedar_diagnostics(
            "repository",
            "read",
            7,
            1,
            &[authz_cedar::CedarEvaluationErrorCategory::AttributeMissing],
        );
    });

    let output = String::from_utf8(buffer.lock().expect("log buffer").clone()).expect("UTF-8 log");
    for expected in [
        "resource_type=\"repository\"",
        "action=\"read\"",
        "policy_version=7",
        "determining_policy_count=1",
        "AttributeMissing",
    ] {
        assert!(
            output.contains(expected),
            "missing allowlisted field {expected}: {output}"
        );
    }
    for forbidden in [
        "tenant_secret_123",
        "principal_user_123",
        "resource_repo_123",
        "Bearer",
        "api_key",
        "entity_attributes",
    ] {
        assert!(
            !output.contains(forbidden),
            "leaked forbidden field {forbidden}"
        );
    }
}

#[test]
fn build_subject_parent_template_dedupes_parents_and_tracks_resource_scopes() {
    let assignments = vec![
        assignment("role_reader", Some("tenant"), None),
        assignment("role_editor", Some("org"), Some("org_1")),
        assignment("role_doc", Some("resource:document"), Some("doc_1")),
    ];
    let relationship_parents = vec![
        parent("org", "org_1"),
        parent("org", "org_1"),
        parent("group", "group_1"),
    ];

    let template = build_subject_parent_template(&assignments, &relationship_parents, "tenant_1");

    assert_eq!(
        template.parents,
        vec![
            parent("group", "group_1"),
            parent("org", "org_1"),
            parent("role", "role_doc"),
            parent("role", "role_editor"),
            parent("role", "role_reader"),
            parent("tenant", "tenant_1"),
        ]
    );
    assert_eq!(
        template.resource_scopes.get("document"),
        Some(&HashSet::from(["doc_1".to_string()]))
    );
}

#[test]
fn enrich_request_with_snapshots_injects_org_properties_without_storage() {
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: vec![parent("org", "org_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        resource_parents: vec![parent("org", "org_2")],
        fetched_at_ms: 1,
    };

    let enriched =
        enrich_request_with_snapshots("tenant_1", request, &subject_access, &resource_access)
            .expect("snapshot enrichment should succeed");

    assert_eq!(
        enriched.request.subject.properties,
        Some(json!({ "org_id": "org_1" }))
    );
    assert_eq!(
        enriched.request.resource.properties,
        Some(json!({ "org_id": "org_2" }))
    );
}

#[test]
fn enrich_request_with_snapshots_rejects_mismatched_resource_snapshot() {
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        resource_type: "document".to_string(),
        resource_id: "doc_2".to_string(),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    let error =
        enrich_request_with_snapshots("tenant_1", request, &subject_access, &resource_access)
            .expect_err("wrong resource snapshot should fail closed");

    assert!(matches!(
        error,
        crate::AuthzRuntimeError::ResourceSnapshotMismatch
    ));
}

#[test]
fn inject_internal_context_replaces_non_object_context_with_reserved_object() {
    let mut request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: Some(Context {
            attributes: json!("not-an-object"),
        }),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    inject_internal_context(&mut request, json!({ "token_present": false }));

    assert_eq!(
        request.context.map(|context| context.attributes),
        Some(json!({ "_authz": { "token_present": false } }))
    );
}

#[test]
fn typed_internal_context_preserves_non_object_context_normalization() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: Some(Context::new(json!("not-an-object"))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                subject_access: SubjectAccessSnapshot {
                    subject: request.subject.clone(),
                    assignments: vec![assignment("reader", Some("tenant"), None)],
                    subject_parents: vec![
                        parent("role", "reader"),
                        parent("tenant", "tenant_1"),
                    ],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
                request,
            },
            now,
        )
        .expect("non-object context is normalized");

    assert!(response.decision);
}

#[test]
fn effective_assignments_filter_expired_entries_at_supplied_clock() {
    let now = Utc
        .timestamp_opt(1_800_000_000, 0)
        .single()
        .expect("test timestamp should be valid");
    let snapshot = SubjectAccessSnapshot {
        subject: Subject::user("user_1"),
        assignments: vec![
            assignment("role_active", Some("tenant"), None),
            EffectiveRoleAssignment {
                expires_at: Some(now - chrono::Duration::seconds(1)),
                ..assignment("role_expired", Some("tenant"), None)
            },
        ],
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };

    let active = snapshot.active_assignments_at(now);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].role_id, "role_active");
}

#[test]
fn incomplete_jwt_context_cannot_grant_role_permissions() {
    let runtime = runtime_with_read_role();
    let subject = Subject::user("user_1");
    let request = EvaluationRequest {
        subject: subject.clone(),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: Some(JwtContext {
            roles: vec![RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Global,
            }],
            roles_complete: false,
            claims_complete: true,
            ..JwtContext::default()
        }),
        session_context: None,
        token_context: None,
    };

    let scoped = permissions_for_request_bits(&runtime, &[], &request, &subject);
    let decision = action_policy_decision_bits(
        &runtime,
        "document",
        "read",
        &scoped.permissions,
        &scoped.checked_roles,
        true,
    );

    assert_eq!(decision, ActionPolicyDecision::NoPolicyAllow);
}

#[test]
fn complete_jwt_context_can_grant_role_permissions() {
    let runtime = runtime_with_read_role();
    let subject = Subject::user("user_1");
    let request = EvaluationRequest {
        subject: subject.clone(),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: Some(JwtContext {
            roles: vec![RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Global,
            }],
            ..JwtContext::default()
        }),
        session_context: None,
        token_context: None,
    };

    let scoped = permissions_for_request_bits(&runtime, &[], &request, &subject);
    let decision = action_policy_decision_bits(
        &runtime,
        "document",
        "read",
        &scoped.permissions,
        &scoped.checked_roles,
        true,
    );

    assert_eq!(decision, ActionPolicyDecision::AllowMatched);
}

#[test]
fn public_resource_does_not_allow_undeclared_read_action() {
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
        permissions: vec![],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    };
    let runtime = build_runtime(config);
    let evaluator = LocalAuthzEvaluator::new(runtime);
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1").with_properties(json!({"is_public": true})),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        subject_access: SubjectAccessSnapshot {
            subject: request.subject.clone(),
            assignments: vec![],
            subject_parents: vec![],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            resource_parents: vec![],
            fetched_at_ms: 1,
        },
        request,
    };
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    let response = evaluator.evaluate_at(input, now).expect("evaluation");

    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("no_policy_allow".to_string())
    );
}

fn runtime_with_read_role() -> EvaluationRuntime {
    build_runtime(ConfigurationModel {
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
            id: "document:read".into(),
            name: "Document reader".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:read").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        scope_mappings: vec![ScopeMappingEntry {
            scope: "document:read".to_string(),
            permissions: vec!["document:read".to_string()],
            includes: vec![],
        }],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

#[test]
fn token_expiry_given_reused_subject_snapshot_then_never_reuses_prior_allow_decision() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let input = |expires_at| LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: Subject::user("user_1"),
            resource: Resource::new("document", "doc_1"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: Some(TokenContext {
                token_id: "token_variant".to_string(),
                owner_id: "user_1".to_string(),
                scopes: TokenScopeConfig::with_scopes(vec!["document:read".to_string()]),
                expires_at: Some(expires_at),
            }),
        },
        subject_access: SubjectAccessSnapshot {
            subject: Subject::user("user_1"),
            assignments: vec![assignment("reader", Some("tenant"), None)],
            subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
    };

    let allowed = evaluator
        .evaluate_at(input(2_000), now)
        .expect("valid token");
    let expired = evaluator
        .evaluate_at(input(999), now)
        .expect("expired token");

    assert!(allowed.decision);
    assert!(!expired.decision);
    assert_eq!(
        expired.context.and_then(|context| context.reason),
        Some("token_expired".to_string())
    );
}

#[test]
fn token_variants_given_reused_subject_snapshot_then_each_decision_uses_current_token_context() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let subject_access = SubjectAccessSnapshot {
        subject: Subject::user("user_1"),
        assignments: vec![assignment("reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let evaluate = |token_context| {
        evaluator
            .evaluate_at(
                LocalEvaluationInput {
                    tenant_id: "tenant_1".to_string(),
                    request: EvaluationRequest {
                        subject: Subject::user("user_1"),
                        resource: Resource::new("document", "doc_1"),
                        action: Action::new("read"),
                        context: None,
                        jwt_context: None,
                        session_context: None,
                        token_context: Some(token_context),
                    },
                    subject_access: subject_access.clone(),
                    resource_access: ResourceAccessSnapshot {
                        resource_type: "document".to_string(),
                        resource_id: "doc_1".to_string(),
                        resource_parents: vec![parent("tenant", "tenant_1")],
                        fetched_at_ms: 1,
                    },
                },
                now,
            )
            .expect("token evaluation")
    };
    let token = |token_id: &str, owner_id: &str, scopes: Vec<&str>, expires_at| TokenContext {
        token_id: token_id.to_string(),
        owner_id: owner_id.to_string(),
        scopes: TokenScopeConfig::with_scopes(scopes.into_iter().map(str::to_string).collect()),
        expires_at: Some(expires_at),
    };

    assert!(evaluate(token("token_allow", "user_1", vec!["document:read"], 2_000)).decision);
    assert!(
        !evaluate(token(
            "token_scope",
            "user_1",
            vec!["document:write"],
            2_000
        ))
        .decision
    );
    assert!(evaluate(token("token_owner", "user_2", vec!["document:read"], 2_000)).decision);
    assert!(!evaluate(token("token_expired", "user_1", vec!["document:read"], 999)).decision);
    let selected_other_resource = TokenContext {
        token_id: "token_selected_resource".to_string(),
        owner_id: "user_1".to_string(),
        scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::Selected,
            selected_resources: vec!["doc_2".to_string()],
            resource_permissions: HashMap::from([(
                "document".to_string(),
                vec!["document:read".to_string()],
            )]),
            org_permissions: HashMap::new(),
        }),
        expires_at: Some(2_000),
    };
    assert!(!evaluate(selected_other_resource).decision);
}

#[test]
fn borrowed_and_owned_local_inputs_have_identical_decisions() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        subject: request.subject.clone(),
        assignments: vec![assignment("reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        resource_parents: vec![parent("tenant", "tenant_1")],
        fetched_at_ms: 1,
    };

    let owned = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: request.clone(),
                subject_access: subject_access.clone(),
                resource_access: resource_access.clone(),
            },
            now,
        )
        .expect("owned evaluation");
    let borrowed = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1",
                request,
                subject_access: &subject_access,
                resource_access: &resource_access,
            },
            now,
        )
        .expect("borrowed evaluation");

    assert_eq!(
        serde_json::to_value(borrowed).expect("borrowed response JSON"),
        serde_json::to_value(owned).expect("owned response JSON"),
    );
}

#[test]
#[ignore = "P2-036 borrowed batch-input allocation and CPU receipt"]
fn borrowed_local_input_avoids_snapshot_clones_profile() {
    const ITERATIONS: usize = 10_000;

    let tenant_id = "tenant_1";
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        subject: request.subject.clone(),
        assignments: (0..64)
            .map(|index| assignment(&format!("reader_{index}"), Some("tenant"), None))
            .collect(),
        subject_parents: (0..64)
            .map(|index| parent("role", &format!("reader_{index}")))
            .collect(),
        resource_scopes: HashMap::from([(
            "document".to_string(),
            (0..64).map(|index| format!("doc_{index}")).collect(),
        )]),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        resource_parents: (0..16)
            .map(|index| parent("group", &format!("group_{index}")))
            .collect(),
        fetched_at_ms: 1,
    };

    let owned_guard = AllocationGuard::start(
        module_path!(),
        "borrowed_local_input_avoids_snapshot_clones_profile",
        file!(),
        line!(),
        Some("owned_local_input"),
    );
    for _ in 0..ITERATIONS {
        black_box(LocalEvaluationInput {
            tenant_id: tenant_id.to_string(),
            request: request.clone(),
            subject_access: subject_access.clone(),
            resource_access: resource_access.clone(),
        });
    }
    let owned_allocations = owned_guard.finish();

    let borrowed_guard = AllocationGuard::start(
        module_path!(),
        "borrowed_local_input_avoids_snapshot_clones_profile",
        file!(),
        line!(),
        Some("borrowed_local_input"),
    );
    for _ in 0..ITERATIONS {
        black_box(LocalEvaluationInput {
            tenant_id,
            request: request.clone(),
            subject_access: &subject_access,
            resource_access: &resource_access,
        });
    }
    let borrowed_allocations = borrowed_guard.finish();

    let mut owned_ns = 0_u128;
    let mut borrowed_ns = 0_u128;
    for iteration in 0..ITERATIONS {
        if iteration % 2 == 0 {
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id,
                request: request.clone(),
                subject_access: &subject_access,
                resource_access: &resource_access,
            });
            borrowed_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id: tenant_id.to_string(),
                request: request.clone(),
                subject_access: subject_access.clone(),
                resource_access: resource_access.clone(),
            });
            owned_ns += started.elapsed().as_nanos();
        } else {
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id: tenant_id.to_string(),
                request: request.clone(),
                subject_access: subject_access.clone(),
                resource_access: resource_access.clone(),
            });
            owned_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id,
                request: request.clone(),
                subject_access: &subject_access,
                resource_access: &resource_access,
            });
            borrowed_ns += started.elapsed().as_nanos();
        }
    }

    assert!(
        borrowed_allocations.allocation_count < owned_allocations.allocation_count,
        "borrowed allocations={} owned allocations={}",
        borrowed_allocations.allocation_count,
        owned_allocations.allocation_count,
    );
    eprintln!(
        "p2_036_borrowed_input_profile|iterations={ITERATIONS}|owned_allocations={}|borrowed_allocations={}|owned_bytes={}|borrowed_bytes={}|owned_ns={owned_ns}|borrowed_ns={borrowed_ns}",
        owned_allocations.allocation_count,
        borrowed_allocations.allocation_count,
        owned_allocations.allocated_bytes,
        borrowed_allocations.allocated_bytes,
    );
}

#[test]
#[ignore = "P2-017 typed internal-context allocation and CPU receipt"]
fn typed_internal_context_avoids_json_round_trip_profile() {
    const ITERATIONS: usize = 2_000;

    let runtime = runtime_with_read_role();
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let request = EvaluationRequest {
        subject: Subject::user("user_1").with_properties(json!({
            "department": "engineering"
        })),
        resource: Resource::new("document", "doc_1").with_properties(json!({
            "org_id": "org_1",
            "classification": "internal"
        })),
        action: Action::new("read"),
        context: Some(Context::new(json!({
            "request_region": "eu-west-1",
            "risk_score": 3
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        subject_access: SubjectAccessSnapshot {
            subject: request.subject.clone(),
            assignments: vec![assignment(
                "reader",
                Some("resource:document"),
                Some("doc_1"),
            )],
            subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
        request,
    };

    let legacy_guard = AllocationGuard::start(
        module_path!(),
        "typed_internal_context_avoids_json_round_trip_profile",
        file!(),
        line!(),
        Some("legacy_json_internal_context"),
    );
    black_box(prepare_legacy_internal_context(&runtime, &input, now));
    let legacy_allocations = legacy_guard.finish();

    let typed_guard = AllocationGuard::start(
        module_path!(),
        "typed_internal_context_avoids_json_round_trip_profile",
        file!(),
        line!(),
        Some("typed_cedar_internal_context"),
    );
    black_box(prepare_typed_internal_context(&runtime, &input, now));
    let typed_allocations = typed_guard.finish();

    let mut legacy_ns = 0_u128;
    let mut typed_ns = 0_u128;
    for iteration in 0..ITERATIONS {
        if iteration % 2 == 0 {
            let started = Instant::now();
            black_box(prepare_typed_internal_context(&runtime, &input, now));
            typed_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(prepare_legacy_internal_context(&runtime, &input, now));
            legacy_ns += started.elapsed().as_nanos();
        } else {
            let started = Instant::now();
            black_box(prepare_legacy_internal_context(&runtime, &input, now));
            legacy_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(prepare_typed_internal_context(&runtime, &input, now));
            typed_ns += started.elapsed().as_nanos();
        }
    }

    eprintln!(
        "p2_017_internal_context_profile|iterations={ITERATIONS}|legacy_allocations={}|typed_allocations={}|legacy_bytes={}|typed_bytes={}|legacy_ns={legacy_ns}|typed_ns={typed_ns}",
        legacy_allocations.allocation_count,
        typed_allocations.allocation_count,
        legacy_allocations.allocated_bytes,
        typed_allocations.allocated_bytes,
    );
}

fn build_runtime(config: ConfigurationModel) -> EvaluationRuntime {
    let config = config.into_validated().expect("valid config");
    let bundle = authz_cedar::compile_policy_bundle(&config, 1).expect("compiled bundle");
    EvaluationRuntime::build(config, &bundle).expect("runtime")
}

fn assignment(
    role_id: &str,
    scope_type: Option<&str>,
    scope_id: Option<&str>,
) -> EffectiveRoleAssignment {
    EffectiveRoleAssignment {
        principal_id: Some("user_1".to_string()),
        role_id: role_id.to_string(),
        scope_type: scope_type.map(ToString::to_string),
        scope_id: scope_id.map(ToString::to_string),
        expires_at: None,
    }
}

fn parent(ref_type: &str, id: &str) -> ParentRef {
    ParentRef {
        ref_type: ref_type.to_string(),
        id: id.to_string(),
    }
}
