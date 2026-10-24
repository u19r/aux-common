use std::{
    collections::{HashMap, HashSet},
    hint::black_box,
    sync::Arc,
    time::Instant,
};

use alloc_counter::AllocationGuard;
use authz_types::{
    AccessAssignmentMode, AccessAssignmentPolicySpec, AcrLevel, Action, ConfigurationModel,
    Context, EvaluationRequest, FineGrainedScopes, JwtContext, MAX_BATCH_EVALUATIONS,
    MAX_PERMISSIONS, MAX_ROLES, PermissionActionRef, PermissionId, Resource, ResourceSelection,
    RoleActionRef, RoleAssignment, RoleScope, Scope, ScopeMappingEntry, SessionContext,
    StepUpConfig, StepUpRule, Subject, TokenContext, TokenScopeConfig, TokenSubjectBinding,
};
use chrono::{TimeZone, Utc};
use serde_json::json;

use crate::{
    ActionPolicyDecision, EffectiveRoleAssignment, EvaluationRuntime, LocalAuthzEvaluator,
    LocalBatchEvaluationInput, LocalEvaluationInput, ParentRef, ResourceAccessSnapshot,
    SnapshotFreshnessPolicy, SubjectAccessSnapshot, TrustedAuthorizationContext,
    action_policy_decision_bits, best_permission_for_action_with_bits,
    build_subject_parent_template, local::inject_internal_context, permissions_for_request_bits,
};

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
        &input.trusted_context,
        &input.request.subject,
        &input.subject_access.subject_parents,
    );
    let internal = crate::local::build_internal_context_at(
        runtime,
        &input.request,
        &scoped.permissions,
        input.trusted_context.token_context(),
        &assignments,
        input.trusted_context.session_context(),
        now,
    );
    let mut enriched = crate::enrich_request_with_snapshots_at(
        &input.tenant_id,
        input.request.clone(),
        &input.trusted_context,
        &input.subject_access,
        &input.resource_access,
        now,
        crate::SnapshotFreshnessPolicy::for_tests(),
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
    authz_cedar::prepare_evaluation_owned_with_trusted_parents(
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
        &input.trusted_context,
        &input.request.subject,
        &input.subject_access.subject_parents,
    );
    let internal = crate::local::build_cedar_internal_context_at(
        runtime,
        &input.request,
        &scoped.permissions,
        input.trusted_context.token_context(),
        &assignments,
        input.trusted_context.session_context(),
        now,
    )
    .expect("typed internal context");
    let enriched = crate::enrich_request_with_snapshots_at(
        &input.tenant_id,
        input.request.clone(),
        &input.trusted_context,
        &input.subject_access,
        &input.resource_access,
        now,
        crate::SnapshotFreshnessPolicy::for_tests(),
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
    authz_cedar::prepare_evaluation_owned_with_registry_and_trusted_internal_context(
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
        crate::local::record_cedar_diagnostics(
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
        subject: Subject::user("user_1").with_properties(json!({
            "org_id": "caller_org",
            "group_id": "caller_group"
        })),
        resource: Resource::new("document", "doc_1").with_properties(json!({
            "org_id": "caller_org",
            "is_public": true,
            "owner_id": "caller_owner"
        })),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1").with_properties(json!({
            "org_id": "org_1",
            "group_id": "group_1"
        })),
        assignments: Vec::new(),
        subject_parents: vec![parent("org", "org_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({
            "org_id": "org_2",
            "is_public": false,
            "owner_id": "owner_2"
        }),
        resource_parents: vec![parent("org", "org_2")],
        fetched_at_ms: 1,
    };

    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc::now(),
        crate::SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("snapshot enrichment should succeed");

    assert_eq!(
        enriched.request.subject.properties,
        Some(json!({ "org_id": "org_1", "group_id": "group_1" }))
    );
    assert_eq!(
        enriched.request.resource.properties,
        Some(json!({
            "org_id": "org_2",
            "is_public": false,
            "owner_id": "owner_2"
        }))
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
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_2".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc::now(),
        crate::SnapshotFreshnessPolicy::for_tests(),
    )
    .expect_err("wrong resource snapshot should fail closed");

    assert!(matches!(
        error,
        crate::AuthzRuntimeError::ResourceSnapshotMismatch
    ));
}

#[test]
fn enrich_request_with_snapshots_rejects_stale_subject_snapshot() {
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
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1_000,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 600_000,
    };

    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_millis_opt(600_000)
            .single()
            .expect("test timestamp"),
        SnapshotFreshnessPolicy::new(
            std::time::Duration::from_millis(5_000),
            std::time::Duration::from_millis(30),
        ),
    )
    .expect_err("stale subject snapshot must fail closed");

    assert!(matches!(
        error,
        crate::AuthzRuntimeError::SnapshotStale {
            snapshot: "subject"
        }
    ));
}

#[test]
fn enrich_request_with_snapshots_rejects_future_resource_snapshot() {
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
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 100_000,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 100_200,
    };

    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_millis_opt(100_000)
            .single()
            .expect("test timestamp"),
        SnapshotFreshnessPolicy::new(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_millis(30),
        ),
    )
    .expect_err("future resource snapshot must fail closed");

    assert!(matches!(
        error,
        crate::AuthzRuntimeError::SnapshotTimestampInvalid {
            snapshot: "resource"
        }
    ));
}

#[test]
fn local_evaluator_default_policy_rejects_stale_snapshots() {
    let evaluator = LocalAuthzEvaluator::from_arc(Arc::new(runtime_with_read_role()));
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let now = Utc
        .timestamp_millis_opt(600_000)
        .single()
        .expect("test timestamp");
    let error = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: Vec::new(),
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: Vec::new(),
                    fetched_at_ms: 600_000,
                },
            },
            now,
        )
        .expect_err("default evaluator policy must reject stale snapshots");

    assert!(matches!(
        error,
        crate::AuthzRuntimeError::SnapshotStale {
            snapshot: "subject"
        }
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
                    tenant_id: "tenant_1".to_string(),
                    subject: request.subject.clone(),
                    assignments: vec![assignment("reader", Some("tenant"), None)],
                    subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
                request,
                trusted_context: TrustedAuthorizationContext::default(),
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
        tenant_id: "tenant_1".to_string(),
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

    let scoped = permissions_for_request_bits(
        &runtime,
        &[],
        &request,
        &TrustedAuthorizationContext::default(),
        &subject,
        &[],
    );
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
        jwt_context: Some(JwtContext::complete(
            Vec::new(),
            Vec::new(),
            vec![RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Global,
            }],
        )),
        session_context: None,
        token_context: None,
    };

    let scoped = permissions_for_request_bits(
        &runtime,
        &[],
        &request,
        &TrustedAuthorizationContext::from_validated_parts(
            &subject,
            request.jwt_context.clone(),
            None,
            None,
        ),
        &subject,
        &[],
    );
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
fn local_evaluator_ignores_wire_jwt_context_without_trusted_context() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        // This is deliberately a complete-looking but unverified wire value.
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
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: Vec::new(),
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: Vec::new(),
                    fetched_at_ms: 1,
                },
            },
            now,
        )
        .expect("evaluation");

    assert!(
        !response.decision,
        "wire JWT claims must not become Cedar role parents without validation"
    );
}

#[test]
fn local_evaluator_accepts_jwt_only_when_context_is_explicitly_trusted() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let jwt_context = JwtContext::complete(
        Vec::new(),
        Vec::new(),
        vec![RoleAssignment {
            role_id: "reader".to_string(),
            scope: RoleScope::Global,
        }],
    );
    let response = evaluator
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
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::from_validated_parts(
                    &Subject::user("user_1"),
                    Some(jwt_context),
                    None,
                    None,
                ),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: Vec::new(),
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: Vec::new(),
                    fetched_at_ms: 1,
                },
            },
            now,
        )
        .expect("evaluation");

    assert!(
        response.decision,
        "validated JWT roles should still be usable"
    );
}

#[test]
fn trusted_context_bound_to_another_subject_is_rejected() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let jwt_context = JwtContext::complete(
        Vec::new(),
        Vec::new(),
        vec![RoleAssignment {
            role_id: "reader".to_string(),
            scope: RoleScope::Global,
        }],
    );

    let result = evaluator.evaluate_at(
        LocalEvaluationInput {
            tenant_id: "tenant_1".to_string(),
            request: EvaluationRequest {
                subject: Subject::user("user_2"),
                resource: Resource::new("document", "doc_1"),
                action: Action::new("read"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            trusted_context: TrustedAuthorizationContext::from_validated_parts(
                &Subject::user("user_1"),
                Some(jwt_context),
                None,
                None,
            ),
            subject_access: SubjectAccessSnapshot {
                tenant_id: "tenant_1".to_string(),
                subject: Subject::user("user_2"),
                assignments: Vec::new(),
                subject_parents: Vec::new(),
                resource_scopes: HashMap::new(),
                fetched_at_ms: 1,
            },
            resource_access: ResourceAccessSnapshot {
                tenant_id: "tenant_1".to_string(),
                resource_type: "document".to_string(),
                resource_id: "doc_1".to_string(),
                properties: json!({}),
                resource_parents: Vec::new(),
                fetched_at_ms: 1,
            },
        },
        now,
    );

    assert!(matches!(
        result,
        Err(crate::AuthzRuntimeError::TrustedContextSubjectMismatch)
    ));
}

#[test]
fn snapshot_enrichment_ignores_wire_jwt_context_without_trusted_context() {
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
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
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("snapshot enrichment");

    assert!(
        enriched.subject_parents.is_empty(),
        "wire JWT roles must not become trusted subject parents"
    );
}

#[test]
fn given_wire_session_and_token_context_without_trusted_context_when_enriching_then_discards_both()
{
    // Given wire credentials that would otherwise change the evaluation.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: Some(SessionContext::with_mfa(900, 950, "otp")),
        token_context: Some(TokenContext {
            expires_at: Some(999),
            ..TokenContext::new(
                "wire_token".to_string(),
                "user_1".to_string(),
                TokenScopeConfig::full_access(),
            )
        }),
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: vec![assignment("reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: vec![parent("tenant", "tenant_1")],
        fetched_at_ms: 1,
    };

    // When enriching without a caller-validated authorization context.
    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request.clone(),
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("wire credentials are not an enrichment source");
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access,
                resource_access,
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    // Then both fields are cleared and the expired wire token cannot deny the
    // request.
    assert!(enriched.request.session_context.is_none());
    assert!(enriched.request.token_context.is_none());
    assert!(response.decision);
}

#[test]
fn mismatched_jwt_resource_roles_are_not_added_to_cedar_parents() {
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: Some(JwtContext {
            roles: vec![RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: "document".to_string(),
                    resource_id: "doc_2".to_string(),
                },
            }],
            ..JwtContext::default()
        }),
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc::now(),
        crate::SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("snapshot enrichment");
    assert!(
        !enriched
            .subject_parents
            .iter()
            .any(|parent| parent.ref_type == "role" && parent.id == "reader")
    );
}

#[test]
fn off_scope_snapshot_role_parent_cannot_grant_a_tenant_role() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: request.subject.clone(),
                    assignments: vec![assignment(
                        "reader",
                        Some("resource:document"),
                        Some("doc_2"),
                    )],
                    subject_parents: vec![parent("role", "reader")],
                    resource_scopes: HashMap::from([(
                        "document".to_string(),
                        HashSet::from(["doc_2".to_string()]),
                    )]),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![],
                    fetched_at_ms: 1,
                },
                request,
                trusted_context: TrustedAuthorizationContext::default(),
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(!response.decision, "off-scope role parent must not allow");
}

#[test]
fn given_cross_tenant_snapshot_when_evaluating_then_rejects() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let result = evaluator.evaluate_at(
        LocalEvaluationInput {
            tenant_id: "tenant_1".to_string(),
            subject_access: SubjectAccessSnapshot {
                tenant_id: "tenant_2".to_string(),
                subject: request.subject.clone(),
                assignments: Vec::new(),
                subject_parents: Vec::new(),
                resource_scopes: HashMap::new(),
                fetched_at_ms: 1,
            },
            resource_access: ResourceAccessSnapshot {
                tenant_id: "tenant_1".to_string(),
                resource_type: "document".to_string(),
                resource_id: "doc_1".to_string(),
                properties: json!({}),
                resource_parents: Vec::new(),
                fetched_at_ms: 1,
            },
            request,
            trusted_context: TrustedAuthorizationContext::default(),
        },
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    );

    assert!(matches!(
        result,
        Err(crate::AuthzRuntimeError::TenantSnapshotMismatch)
    ));
}

#[test]
fn given_role_subject_with_out_of_scope_assignment_when_evaluating_then_denies() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let result = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: EvaluationRequest {
                    subject: Subject::role("reader"),
                    resource: Resource::new("document", "doc_1"),
                    action: Action::new("read"),
                    context: None,
                    jwt_context: None,
                    session_context: None,
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::role("reader"),
                    assignments: vec![role_assignment(
                        "reader",
                        "reader",
                        Some("org"),
                        Some("org_denied"),
                    )],
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({"org_id": "org_allowed"}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(
        !result.decision,
        "role identity must not bypass an out-of-scope assignment"
    );
}

#[test]
fn given_role_subject_without_assignment_when_role_is_tenant_scoped_then_allows() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let result = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: EvaluationRequest {
                    subject: Subject::role("reader"),
                    resource: Resource::new("document", "doc_1"),
                    action: Action::new("read"),
                    context: None,
                    jwt_context: None,
                    session_context: None,
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::role("reader"),
                    assignments: Vec::new(),
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(
        result.decision,
        "tenant-scoped role subjects retain compatibility"
    );
}

#[test]
fn given_role_subject_assignment_for_foreign_principal_when_scoping_then_denies() {
    let runtime = runtime_with_read_role();
    let request = EvaluationRequest {
        subject: Subject::role("reader"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let scoped = permissions_for_request_bits(
        &runtime,
        &[assignment("reader", Some("tenant"), None)],
        &request,
        &TrustedAuthorizationContext::default(),
        &request.subject,
        &[],
    );

    assert!(!scoped.permissions.contains(0));
}

#[test]
fn given_trusted_group_parent_when_group_assignment_scopes_user_then_allows() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: request.subject.clone(),
                    assignments: vec![role_assignment("reader", "group_1", Some("tenant"), None)],
                    subject_parents: vec![
                        parent("group", "group_1"),
                        parent("role", "reader"),
                        parent("tenant", "tenant_1"),
                    ],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(response.decision, "trusted group parent should grant role");
}

#[test]
fn given_foreign_group_assignment_without_parent_when_evaluating_then_denies() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: request.subject.clone(),
                    assignments: vec![role_assignment(
                        "reader",
                        "group_foreign",
                        Some("tenant"),
                        None,
                    )],
                    subject_parents: vec![
                        parent("group", "group_1"),
                        parent("role", "reader"),
                        parent("tenant", "tenant_1"),
                    ],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(!response.decision, "foreign group must not grant role");
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
            tenant_id: "tenant_1".to_string(),
            subject: request.subject.clone(),
            assignments: vec![],
            subject_parents: vec![],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            properties: json!({}),
            resource_parents: vec![],
            fetched_at_ms: 1,
        },
        request,
        trusted_context: TrustedAuthorizationContext::default(),
    };
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    let response = evaluator.evaluate_at(input, now).expect("evaluation");

    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("no_policy_allow".to_string())
    );
}

#[test]
fn caller_resource_org_cannot_override_snapshot_org_for_org_scope() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_read_role());
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1")
            .with_properties(json!({ "org_id": "org_allowed" })),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    let response = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: request.subject.clone(),
                    assignments: vec![assignment("reader", Some("org"), Some("org_allowed"))],
                    subject_parents: vec![parent("role", "reader"), parent("org", "org_allowed")],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("org", "org_actual")],
                    fetched_at_ms: 1,
                },
                request,
                trusted_context: TrustedAuthorizationContext::default(),
            },
            now,
        )
        .expect("evaluation");

    assert!(
        !response.decision,
        "a caller-controlled org_id must not grant access to an unrelated resource"
    );
}

#[test]
fn given_empty_action_batch_when_evaluating_then_returns_no_decisions() {
    // Given an otherwise valid request and access snapshots but no actions.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
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
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    // When evaluating an empty action sequence.
    let responses = evaluator
        .evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: "tenant_1",
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                actions: &[],
                subject_access: &subject_access,
                resource_access: &resource_access,
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("empty batches are a valid no-op");

    // Then no authorization decision is produced.
    assert!(responses.is_empty());
}

#[test]
fn given_token_bound_to_another_org_when_evaluating_then_denies_before_policy() {
    // Given a valid token whose organization binding differs from the resource.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let subject = Subject::user("user_1");
    let token = TokenContext::new(
        "token_org_other".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::full_access()
            .with_org("org_allowed".to_string())
            .expect("valid organization binding"),
    );
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: subject.clone(),
            resource: Resource::new("organization", "org_denied")
                .with_properties(json!({"org_id": "org_denied"})),
            action: Action::new("manage"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &subject,
            None,
            None,
            Some(token),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: subject.clone(),
            assignments: vec![assignment("org_manager", Some("tenant"), None)],
            subject_parents: vec![parent("role", "org_manager"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org_denied".to_string(),
            properties: json!({"org_id": "org_denied"}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
    };

    // When evaluating the organization-bound request.
    let response = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("token organization mismatch is a deny response");

    // Then the token ceiling rejects before Cedar can evaluate the policy.
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("token_org_mismatch".to_string())
    );
}

#[test]
fn given_subject_token_without_owner_org_assignment_when_evaluating_then_denies() {
    // Given a subject-bound token for an organization the owner does not hold.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let subject = Subject::user("user_1");
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: subject.clone(),
            resource: Resource::new("organization", "org_allowed")
                .with_properties(json!({"org_id": "org_allowed"})),
            action: Action::new("manage"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &subject,
            None,
            None,
            Some(TokenContext::new(
                "token_owner_org".to_string(),
                "user_1".to_string(),
                TokenScopeConfig::full_access()
                    .with_org("org_allowed".to_string())
                    .expect("valid organization binding"),
            )),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: subject.clone(),
            assignments: vec![assignment("org_manager", Some("tenant"), None)],
            subject_parents: vec![parent("role", "org_manager"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org_allowed".to_string(),
            properties: json!({"org_id": "org_allowed"}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
    };

    // When evaluating the request with a tenant-only owner snapshot.
    let response = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("owner organization mismatch is a deny response");

    // Then an org-bound token cannot elevate a tenant-only owner.
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("token_org_mismatch".to_string())
    );
}

#[test]
fn given_session_context_when_building_internal_context_then_preserves_trusted_ages() {
    // Given a trusted session with known authentication and MFA timestamps.
    let runtime = runtime_with_read_role();
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let session = SessionContext::with_mfa(900, 950, "otp");

    // When translating the session into Cedar's typed internal context.
    let internal = crate::local::build_cedar_internal_context_at(
        &runtime,
        &request,
        &crate::PermissionBits::default(),
        None,
        &[],
        Some(&session),
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    )
    .expect("session context should be representable");

    // Then Cedar receives the assurance level, methods, and non-negative ages.
    assert!(internal.session_present);
    assert_eq!(internal.session_acr, 2);
    assert_eq!(internal.session_amr, vec!["pwd", "otp"]);
    assert!(internal.session_auth_age_present);
    assert_eq!(internal.session_auth_age_seconds, 100);
    assert!(internal.session_mfa_age_present);
    assert_eq!(internal.session_mfa_age_seconds, 50);
}

#[test]
fn given_non_positive_snapshot_timestamp_when_enriching_then_rejects_timestamp() {
    // Given a request whose subject snapshot has no trustworthy fetch time.
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
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 0,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1_000,
    };

    // When enriching at a deterministic clock.
    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_millis_opt(1_000).single().expect("timestamp"),
        SnapshotFreshnessPolicy::default(),
    )
    .expect_err("non-positive snapshot timestamps must fail closed");

    // Then the runtime reports invalid provenance rather than evaluating.
    assert!(matches!(
        error,
        crate::AuthzRuntimeError::SnapshotTimestampInvalid {
            snapshot: "subject"
        }
    ));
}

#[test]
fn given_subject_snapshot_for_another_subject_when_enriching_then_rejects() {
    // Given a request whose trusted subject snapshot names a different user.
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
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_2"),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    // When enriching the request with caller-validated snapshots.
    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect_err("subject snapshot mismatch must fail closed");

    // Then no subject identity can borrow another subject's assignments.
    assert!(matches!(
        error,
        crate::AuthzRuntimeError::SubjectSnapshotMismatch
    ));
}

#[test]
fn given_resource_snapshot_from_another_tenant_when_enriching_then_rejects() {
    // Given a resource snapshot fetched for a different tenant.
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
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_2".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    // When enriching under tenant_1.
    let error = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect_err("cross-tenant resource snapshots must fail closed");

    // Then the resource's tenant provenance is rejected before policy use.
    assert!(matches!(
        error,
        crate::AuthzRuntimeError::TenantSnapshotMismatch
    ));
}

#[test]
fn given_resource_scoped_trusted_role_when_enriching_then_copies_resource_org_to_subject() {
    // Given a trusted resource-scoped role and authoritative resource org.
    let subject = Subject::user("user_1").with_properties(json!({"department": "engineering"}));
    let request = EvaluationRequest {
        subject: subject.clone(),
        resource: Resource::new("document", "doc_1")
            .with_properties(json!({"org_id": "caller_org"})),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject,
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::from([(
            "document".to_string(),
            HashSet::from(["doc_1".to_string()]),
        )]),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({"org_id": "org_1", "owner_id": "owner_1"}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    // When enriching with the snapshot authority.
    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("resource-scoped snapshot should enrich");

    // Then caller-supplied resource properties are replaced and subject org is
    // derived safely.
    assert_eq!(
        enriched.request.subject.properties,
        Some(json!({"department": "engineering", "org_id": "org_1"}))
    );
    assert_eq!(
        enriched.request.resource.properties,
        Some(json!({"org_id": "org_1", "owner_id": "owner_1"}))
    );
}

#[test]
fn given_trusted_jwt_org_and_resource_roles_when_enriching_then_adds_only_applicable_parents() {
    // Given trusted JWT roles covering this resource's authoritative
    // organization and id.
    let subject = Subject::user("user_1");
    let jwt_context = JwtContext::complete(
        Vec::new(),
        Vec::new(),
        vec![
            RoleAssignment {
                role_id: "org_reader".to_string(),
                scope: RoleScope::Org {
                    org_id: "org_1".to_string(),
                },
            },
            RoleAssignment {
                role_id: "document_reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                },
            },
            RoleAssignment {
                role_id: "group_reader".to_string(),
                scope: RoleScope::Group {
                    group_id: "group_1".to_string(),
                },
            },
        ],
    );
    let request = EvaluationRequest {
        subject: subject.clone(),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: subject.clone(),
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({"org_id": "org_1"}),
        resource_parents: Vec::new(),
        fetched_at_ms: 1,
    };

    // When enriching using only the explicitly trusted JWT context.
    let enriched = crate::enrich_request_with_snapshots_at(
        "tenant_1",
        request,
        &TrustedAuthorizationContext::from_validated_parts(&subject, Some(jwt_context), None, None),
        &subject_access,
        &resource_access,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        SnapshotFreshnessPolicy::for_tests(),
    )
    .expect("trusted JWT role scopes should enrich");

    // Then matching org/resource roles are present, while group roles remain
    // unsupported here.
    assert!(enriched.subject_parents.contains(&parent("org", "org_1")));
    assert!(
        enriched
            .subject_parents
            .contains(&parent("role", "org_reader"))
    );
    assert!(
        enriched
            .subject_parents
            .contains(&parent("role", "document_reader"))
    );
    assert!(
        !enriched
            .subject_parents
            .contains(&parent("role", "group_reader"))
    );
}

#[test]
fn given_out_of_range_bit_index_when_setting_then_ignores_without_corruption() {
    // Given empty permission and role bitsets.
    let mut permissions = crate::PermissionBits::default();
    let mut roles = crate::RoleBits::default();

    // When callers attempt to set an index outside each fixed capacity.
    permissions.set(MAX_PERMISSIONS);
    roles.set(MAX_ROLES);

    // Then no invalid bit can appear in iteration or intersection checks.
    assert!(!permissions.contains(MAX_PERMISSIONS));
    let mut permission_indices = Vec::new();
    permissions.for_each_set_bit(|index| permission_indices.push(index));
    assert!(permission_indices.is_empty());
    let mut role_indices = Vec::new();
    roles.for_each_set_bit(|index| role_indices.push(index));
    assert!(role_indices.is_empty());
}

#[test]
fn given_scope_mapping_cycle_when_resolving_token_then_unions_each_scope_once() {
    // Given a scope graph whose parent and child include one another.
    let runtime = build_runtime(ConfigurationModel {
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
                id: "document:read".into(),
                name: "Document read".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "read".into(),
                }],
                not_actions: vec![],
            },
            authz_types::Permission {
                id: "document:write".into(),
                name: "Document write".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "write".into(),
                }],
                not_actions: vec![],
            },
        ],
        roles: vec![],
        scope_mappings: vec![
            ScopeMappingEntry {
                scope: "document:read".to_string(),
                permissions: vec!["document:read".to_string()],
                includes: vec!["document:write".to_string()],
            },
            ScopeMappingEntry {
                scope: "document:write".to_string(),
                permissions: vec!["document:write".to_string()],
                includes: vec!["document:read".to_string()],
            },
        ],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    });
    let mut user_permissions = crate::PermissionBits::default();
    user_permissions.set(0);
    user_permissions.set(1);
    let token = TokenContext::new(
        "token_scope_cycle".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
            .expect("valid coarse scope"),
    );

    // When resolving the token's scope against the owner's current permissions.
    let resolved = runtime.resolve_token_permissions_at(
        &user_permissions,
        &token,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    );

    // Then both reachable permissions are retained and cycle traversal
    // terminates.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(0));
    assert!(resolved.permissions.contains(1));
}

#[test]
fn given_persisted_scope_ceiling_when_live_mapping_gains_permission_then_existing_token_stays_narrow()
 {
    // Given a token persisted with read before the current scope maps write
    // too.
    let runtime = runtime_with_read_write_scope_mapping();
    let mut user_permissions = crate::PermissionBits::default();
    user_permissions.set(0);
    user_permissions.set(1);
    let token = TokenContext::new(
        "token_persisted_ceiling".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
            .expect("valid coarse scope")
            .with_resolved_permissions(vec!["document:read".to_string()])
            .expect("valid persisted ceiling"),
    );

    // When resolving against the runtime's broadened live scope mapping.
    let resolved = runtime.resolve_token_permissions_at(
        &user_permissions,
        &token,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    );

    // Then the persisted read ceiling remains authoritative and write stays
    // denied.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(0));
    assert!(!resolved.permissions.contains(1));
}

#[test]
fn given_missing_fine_grained_payload_when_decoding_token_then_rejects_scope() {
    // Given a token marked fine-grained but carrying no fine-grained payload.
    let result = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": null,
    }));

    // Then the canonical deserialization boundary rejects the invalid policy
    // before a runtime token can be created.
    assert!(result.is_err());
}

#[test]
fn given_wildcard_fine_grained_permission_when_resource_bucket_matches_then_allows_permission() {
    // Given a fine-grained token whose document bucket allows every document
    // permission.
    let runtime = runtime_with_read_role();
    let mut user_permissions = crate::PermissionBits::default();
    user_permissions.set(0);
    let token = TokenContext::new(
        "token_wildcard".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::All,
            selected_resources: Vec::new(),
            resource_permissions: HashMap::from([("document".to_string(), vec!["*".to_string()])]),
            org_permissions: HashMap::new(),
        })
        .expect("valid fine-grained scope"),
    );

    // When resolving the token against document:read.
    let resolved = runtime.resolve_token_permissions_at(
        &user_permissions,
        &token,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    );

    // Then the wildcard is accepted only for the declared resource bucket.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(0));
}

#[test]
fn given_wildcard_fine_grained_permission_when_resource_bucket_differs_then_denies_unrelated_permission()
 {
    // Given user permissions for document and project, with a document-only
    // wildcard.
    let runtime = runtime_with_multi_resource_read_role();
    let mut user_permissions = crate::PermissionBits::default();
    user_permissions.set(0);
    user_permissions.set(1);
    let token = TokenContext::new(
        "token_document_wildcard".to_string(),
        "user_1".to_string(),
        TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::All,
            selected_resources: Vec::new(),
            resource_permissions: HashMap::from([("document".to_string(), vec!["*".to_string()])]),
            org_permissions: HashMap::new(),
        })
        .expect("valid fine-grained scope"),
    );

    // When resolving the wildcard against both permission resource types.
    let resolved = runtime.resolve_token_permissions_at(
        &user_permissions,
        &token,
        Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
    );

    // Then wildcard grants document:read but never the unrelated project:read
    // action.
    assert!(resolved.is_valid);
    assert!(resolved.permissions.contains(0));
    assert!(!resolved.permissions.contains(1));
}

#[test]
fn given_default_snapshot_policy_when_age_and_future_skew_reach_boundaries_then_enforces_them() {
    // Given snapshots at the exact default age and future-skew boundaries.
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let now = Utc
        .timestamp_millis_opt(1_000_000)
        .single()
        .expect("timestamp");
    let enrich = |subject_fetched_at_ms, resource_fetched_at_ms| {
        crate::enrich_request_with_snapshots_at(
            "tenant_1",
            request.clone(),
            &TrustedAuthorizationContext::default(),
            &SubjectAccessSnapshot {
                tenant_id: "tenant_1".to_string(),
                subject: request.subject.clone(),
                assignments: Vec::new(),
                subject_parents: Vec::new(),
                resource_scopes: HashMap::new(),
                fetched_at_ms: subject_fetched_at_ms,
            },
            &ResourceAccessSnapshot {
                tenant_id: "tenant_1".to_string(),
                resource_type: "document".to_string(),
                resource_id: "doc_1".to_string(),
                properties: json!({}),
                resource_parents: Vec::new(),
                fetched_at_ms: resource_fetched_at_ms,
            },
            now,
            SnapshotFreshnessPolicy::default(),
        )
    };

    // When enriching at the exact 300-second age and 30-second future skew.
    assert!(enrich(700_000, 1_030_000).is_ok());

    // Then one millisecond beyond either default boundary fails closed.
    assert!(matches!(
        enrich(699_999, 700_000),
        Err(crate::AuthzRuntimeError::SnapshotStale {
            snapshot: "subject"
        })
    ));
    assert!(matches!(
        enrich(700_000, 1_030_001),
        Err(crate::AuthzRuntimeError::SnapshotTimestampInvalid {
            snapshot: "resource"
        })
    ));
}

fn runtime_with_read_role() -> EvaluationRuntime {
    runtime_with_read_role_scope(Scope::Tenant)
}

fn runtime_with_org_read_role() -> EvaluationRuntime {
    runtime_with_read_role_scope(Scope::Org)
}

fn runtime_with_read_role_scope(scope: Scope) -> EvaluationRuntime {
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
                scopes: vec![scope],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: permanent_assignment_policy(),
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

fn runtime_with_read_role_requiring_mfa() -> EvaluationRuntime {
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
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_acr(
            "require_mfa",
            "Require MFA",
            AcrLevel::MultiFactor,
        )],
        step_up_config: HashMap::from([(
            "document".to_string(),
            StepUpConfig {
                default_rule: Some("require_mfa".to_string()),
                action_rules: HashMap::new(),
            },
        )]),
        default_step_up_rule: None,
        description: None,
    })
}

fn runtime_with_role_read_deny() -> EvaluationRuntime {
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
            not_actions: vec![RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
                limit: None,
            }],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

fn runtime_with_batch_actions(count: usize) -> EvaluationRuntime {
    let actions = (0..count)
        .map(|index| authz_types::ActionDefinition {
            name: format!("action_{index}"),
            description: None,
        })
        .collect::<Vec<_>>();
    let permission_actions = actions
        .iter()
        .map(|action| PermissionActionRef {
            resource_type: "document".into(),
            action_name: action.name.clone(),
        })
        .collect::<Vec<_>>();
    build_runtime(ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions,
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:batch".into(),
            name: "Document batch".into(),
            description: None,
            actions: permission_actions,
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "batch_reader".into(),
            name: "Batch reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:batch").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

fn runtime_with_action_permission_catalog(permission_count: usize) -> EvaluationRuntime {
    let permissions = (0..permission_count)
        .map(|index| authz_types::Permission {
            id: format!("document:permission_{index:03}"),
            name: format!("Permission {index}"),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        })
        .collect::<Vec<_>>();
    let role_permissions = permissions
        .iter()
        .map(|permission| authz_types::RolePermission {
            permission_id: PermissionId::new(&permission.id).expect("permission id"),
            scopes: vec![Scope::Tenant],
        })
        .collect();
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
        permissions,
        roles: vec![authz_types::Role {
            id: "catalog_reader".into(),
            name: "Catalog reader".into(),
            description: None,
            permissions: role_permissions,
            actions: vec![],
            not_actions: vec![],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

#[test]
#[ignore = "AC3-003 compiled action descriptor allocation and CPU receipt"]
fn compiled_action_descriptor_profile() {
    const PROFILE_ITERATIONS: usize = 10_000;

    for permission_count in [1, 64] {
        let runtime = runtime_with_action_permission_catalog(permission_count);
        let request = EvaluationRequest {
            subject: Subject::user("user_1"),
            resource: Resource::new("document", "doc_1"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let assignments = vec![assignment("catalog_reader", Some("tenant"), None)];
        let scoped = permissions_for_request_bits(
            &runtime,
            &assignments,
            &request,
            &TrustedAuthorizationContext::default(),
            &request.subject,
            &[],
        );

        let legacy_guard = AllocationGuard::start(
            module_path!(),
            "compiled_action_descriptor_profile",
            file!(),
            line!(),
            Some("legacy"),
        );
        let legacy_started = Instant::now();
        for _ in 0..PROFILE_ITERATIONS {
            black_box(crate::local::legacy_action_resolution_for_profile(
                &runtime,
                "document",
                "read",
                &scoped.permissions,
                &scoped.checked_roles,
            ));
        }
        let legacy_elapsed = legacy_started.elapsed();
        let legacy_report = legacy_guard.finish();

        let compiled_guard = AllocationGuard::start(
            module_path!(),
            "compiled_action_descriptor_profile",
            file!(),
            line!(),
            Some("compiled"),
        );
        let compiled_started = Instant::now();
        for _ in 0..PROFILE_ITERATIONS {
            black_box(crate::local::compiled_action_resolution_for_profile(
                &runtime,
                "document",
                "read",
                &scoped.permissions,
                &scoped.checked_roles,
            ));
        }
        let compiled_elapsed = compiled_started.elapsed();
        let compiled_report = compiled_guard.finish();

        alloc_counter::emit_report(&legacy_report).expect("allocation report");
        alloc_counter::emit_report(&compiled_report).expect("allocation report");
        eprintln!(
            "ac3_003|permissions={permission_count}|iterations={PROFILE_ITERATIONS}|legacy_ns={}|compiled_ns={}",
            legacy_elapsed.as_nanos(),
            compiled_elapsed.as_nanos(),
        );
    }
}

#[test]
#[ignore = "AC3-002 prepared local batch frame allocation and CPU receipt"]
fn prepared_local_batch_frame_profile() {
    const BATCH_ITERATIONS: usize = 100;

    for cardinality in [1, 4, 16] {
        let evaluator = LocalAuthzEvaluator::new(runtime_with_batch_actions(cardinality));
        let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
        let subject_access = SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: Subject::user("user_1"),
            assignments: vec![assignment("batch_reader", Some("tenant"), None)],
            subject_parents: vec![parent("role", "batch_reader")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        };
        let resource_access = ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            properties: json!({}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        };
        let actions = (0..cardinality)
            .map(|index| Action::new(format!("action_{index}")))
            .collect::<Vec<_>>();
        let request = EvaluationRequest {
            subject: Subject::user("user_1"),
            resource: Resource::new("document", "doc_1"),
            action: actions[0].clone(),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let label = match cardinality {
            1 => "one_action",
            4 => "four_actions",
            _ => "sixteen_actions",
        };
        let guard = AllocationGuard::start(
            module_path!(),
            "prepared_local_batch_frame_profile",
            file!(),
            line!(),
            Some(label),
        );
        let started_at = Instant::now();
        for _ in 0..BATCH_ITERATIONS {
            let responses = evaluator
                .evaluate_batch_at(
                    LocalBatchEvaluationInput {
                        tenant_id: "tenant_1",
                        request: request.clone(),
                        trusted_context: TrustedAuthorizationContext::default(),
                        actions: &actions,
                        subject_access: &subject_access,
                        resource_access: &resource_access,
                    },
                    now,
                )
                .expect("batch evaluation");
            black_box(responses);
        }
        let elapsed = started_at.elapsed();
        let report = guard.finish();
        alloc_counter::emit_report(&report).expect("allocation report");
        eprintln!(
            "ac3_002|mode=prepared|cardinality={cardinality}|iterations={BATCH_ITERATIONS}|elapsed_ns={}",
            elapsed.as_nanos(),
        );
    }
}

#[test]
fn prepared_local_batch_matches_individual_action_evaluations() {
    let cardinality = 4;
    let evaluator = LocalAuthzEvaluator::new(runtime_with_batch_actions(cardinality));
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: Subject::user("user_1"),
        assignments: vec![assignment("batch_reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "batch_reader")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: vec![parent("tenant", "tenant_1")],
        fetched_at_ms: 1,
    };
    let actions = (0..cardinality)
        .map(|index| Action::new(format!("action_{index}")))
        .collect::<Vec<_>>();
    let base_request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: actions[0].clone(),
        context: Some(Context::new(json!({"request_region": "eu-west-1"}))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let expected = actions
        .iter()
        .map(|action| {
            let mut request = base_request.clone();
            request.action = action.clone();
            evaluator
                .evaluate_at(
                    LocalEvaluationInput {
                        tenant_id: "tenant_1",
                        request,
                        trusted_context: TrustedAuthorizationContext::default(),
                        subject_access: &subject_access,
                        resource_access: &resource_access,
                    },
                    now,
                )
                .expect("individual evaluation")
        })
        .collect::<Vec<_>>();
    let actual = evaluator
        .evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: "tenant_1",
                request: base_request,
                trusted_context: TrustedAuthorizationContext::default(),
                actions: &actions,
                subject_access: &subject_access,
                resource_access: &resource_access,
            },
            now,
        )
        .expect("prepared batch evaluation");

    assert_eq!(
        serde_json::to_value(actual).expect("actual JSON"),
        serde_json::to_value(expected).expect("expected JSON"),
    );
}

#[test]
fn prepared_local_batch_uses_the_explicit_action_sequence() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_batch_actions(2));
    let actions = vec![Action::new("action_0"), Action::new("action_1")];
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("action_1"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: vec![assignment("batch_reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "batch_reader")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: vec![],
        fetched_at_ms: 1,
    };

    let result = evaluator
        .evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: "tenant_1",
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                actions: &actions,
                subject_access,
                resource_access,
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("batch evaluation");
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|response| response.decision));
}

#[test]
fn oversized_local_batches_are_rejected_before_evaluation() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_batch_actions(1));
    let request = EvaluationRequest {
        subject: Subject::user("user_1"),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("action_0"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: vec![assignment("batch_reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "batch_reader")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: vec![],
        fetched_at_ms: 1,
    };
    let actions = (0..=MAX_BATCH_EVALUATIONS)
        .map(|_| Action::new("action_0"))
        .collect::<Vec<_>>();

    let error = evaluator
        .evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: "tenant_1",
                request,
                trusted_context: TrustedAuthorizationContext::default(),
                actions: &actions,
                subject_access: &subject_access,
                resource_access: &resource_access,
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect_err("oversized batches must be bounded");

    assert!(matches!(error, crate::AuthzRuntimeError::Cedar));
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
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &Subject::user("user_1"),
            None,
            None,
            Some(TokenContext {
                token_id: "token_variant".to_string(),
                owner_id: "user_1".to_string(),
                subject_binding: TokenSubjectBinding::Subject,
                scopes: TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
                    .expect("valid coarse scope"),
                expires_at: Some(expires_at),
            }),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: Subject::user("user_1"),
            assignments: vec![assignment("reader", Some("tenant"), None)],
            subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            properties: json!({}),
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
fn token_expiry_at_exact_evaluation_second_is_denied() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let result = evaluator
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
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::from_validated_parts(
                    &Subject::user("user_1"),
                    None,
                    None,
                    Some(TokenContext {
                        token_id: "token_boundary".to_string(),
                        owner_id: "user_1".to_string(),
                        subject_binding: TokenSubjectBinding::Subject,
                        scopes: TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
                            .expect("valid coarse scope"),
                        expires_at: Some(1_000),
                    }),
                ),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: vec![assignment("reader", Some("tenant"), None)],
                    subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            now,
        )
        .expect("boundary evaluation");

    assert!(!result.decision, "expiration is an exclusive upper bound");
    assert_eq!(
        result.context.and_then(|context| context.reason),
        Some("token_expired".to_string())
    );
}

#[test]
fn token_variants_given_reused_subject_snapshot_then_each_decision_uses_current_token_context() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let subject_access = SubjectAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
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
                        token_context: None,
                    },
                    trusted_context: TrustedAuthorizationContext::from_validated_parts(
                        &Subject::user("user_1"),
                        None,
                        None,
                        Some(token_context),
                    ),
                    subject_access: subject_access.clone(),
                    resource_access: ResourceAccessSnapshot {
                        tenant_id: "tenant_1".to_string(),
                        resource_type: "document".to_string(),
                        resource_id: "doc_1".to_string(),
                        properties: json!({}),
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
        subject_binding: TokenSubjectBinding::Subject,
        scopes: TokenScopeConfig::with_scopes(scopes.into_iter().map(str::to_string).collect())
            .expect("valid coarse scope"),
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
    let owner_mismatch = evaluate(token("token_owner", "user_2", vec!["document:read"], 2_000));
    assert!(!owner_mismatch.decision);
    assert_eq!(
        owner_mismatch.context.and_then(|context| context.reason),
        Some("token_owner_mismatch".to_string())
    );
    let delegated = TokenContext {
        subject_binding: TokenSubjectBinding::Delegated,
        ..token(
            "token_delegated",
            "runtime_caller",
            vec!["document:read"],
            2_000,
        )
    };
    assert!(
        evaluate(delegated).decision,
        "a validated runtime credential must be able to evaluate another subject"
    );
    assert!(!evaluate(token("token_expired", "user_1", vec!["document:read"], 999)).decision);
    let selected_other_resource = TokenContext {
        token_id: "token_selected_resource".to_string(),
        owner_id: "user_1".to_string(),
        subject_binding: TokenSubjectBinding::Subject,
        scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::Selected,
            selected_resources: vec!["doc_2".to_string()],
            resource_permissions: HashMap::from([(
                "document".to_string(),
                vec!["document:read".to_string()],
            )]),
            org_permissions: HashMap::new(),
        })
        .expect("valid fine-grained scope"),
        expires_at: Some(2_000),
    };
    assert!(!evaluate(selected_other_resource).decision);
}

#[test]
fn given_token_owned_by_another_subject_when_evaluating_then_request_is_denied() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let result = evaluator
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
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::from_validated_parts(
                    &Subject::user("user_1"),
                    None,
                    None,
                    Some(TokenContext {
                        token_id: "token_owned_by_user_2".to_string(),
                        owner_id: "user_2".to_string(),
                        subject_binding: TokenSubjectBinding::Subject,
                        scopes: TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
                            .expect("valid coarse scope"),
                        expires_at: Some(2_000),
                    }),
                ),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: vec![assignment("reader", Some("tenant"), None)],
                    subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            now,
        )
        .expect("evaluation");

    assert!(
        !result.decision,
        "a token cannot be replayed by another subject"
    );
    assert_eq!(
        result.context.and_then(|context| context.reason),
        Some("token_owner_mismatch".to_string())
    );
}

#[test]
fn given_non_user_subject_when_bound_token_owner_matches_then_denies() {
    // Given a role subject and a subject-bound token with the same owner id.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let subject = Subject::role("reader");
    let result = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: EvaluationRequest {
                    subject: subject.clone(),
                    resource: Resource::new("document", "doc_1"),
                    action: Action::new("read"),
                    context: None,
                    jwt_context: None,
                    session_context: None,
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::from_validated_parts(
                    &subject,
                    None,
                    None,
                    Some(TokenContext::new(
                        "token_role_owner".to_string(),
                        "reader".to_string(),
                        TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
                            .expect("valid coarse scope"),
                    )),
                ),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: subject.clone(),
                    assignments: Vec::new(),
                    subject_parents: Vec::new(),
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                    properties: json!({}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("matching owner id is still a deny response");

    // Then only a User subject can use a subject-bound token.
    assert!(!result.decision);
    assert_eq!(
        result.context.and_then(|context| context.reason),
        Some("token_owner_mismatch".to_string())
    );
}

#[test]
fn fine_grained_token_must_cover_the_permission_action_resource_type() {
    let runtime = build_runtime(ConfigurationModel {
        version: 1,
        resource_types: vec![
            authz_types::ResourceType {
                id: "alpha".into(),
                name: "Alpha".into(),
                description: None,
                actions: vec![authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                }],
                context_schema: None,
            },
            authz_types::ResourceType {
                id: "beta".into(),
                name: "Beta".into(),
                description: None,
                actions: vec![authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                }],
                context_schema: None,
            },
        ],
        permissions: vec![authz_types::Permission {
            id: "alpha:cross-read".into(),
            name: "Cross-resource read".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "beta".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    });
    let mut user_permissions = crate::PermissionBits::default();
    user_permissions.set(0);
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    let alpha_bucket = TokenContext {
        token_id: "token-alpha".into(),
        owner_id: "user-1".into(),
        subject_binding: TokenSubjectBinding::Subject,
        scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::All,
            selected_resources: vec![],
            resource_permissions: HashMap::from([(
                "alpha".to_string(),
                vec!["alpha:cross-read".to_string()],
            )]),
            org_permissions: HashMap::new(),
        })
        .expect("valid fine-grained scope"),
        expires_at: Some(2_000),
    };
    assert!(
        !runtime
            .resolve_token_permissions_at(&user_permissions, &alpha_bucket, now)
            .permissions
            .contains(0),
        "a permission must not be admitted from an ID prefix unrelated to its actions"
    );

    let beta_bucket = TokenContext {
        scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
            resource_selection: ResourceSelection::All,
            selected_resources: vec![],
            resource_permissions: HashMap::from([(
                "beta".to_string(),
                vec!["alpha:cross-read".to_string()],
            )]),
            org_permissions: HashMap::new(),
        })
        .expect("valid fine-grained scope"),
        ..alpha_bucket
    };
    assert!(
        runtime
            .resolve_token_permissions_at(&user_permissions, &beta_bucket, now)
            .permissions
            .contains(0)
    );
}

#[test]
fn given_selected_id_shared_by_two_resource_types_when_token_is_untyped_then_denies() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_multi_resource_read_role());
    let input = |selected_resources: Vec<String>| LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: Subject::user("user_1"),
            resource: Resource::new("project", "shared-id"),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &Subject::user("user_1"),
            None,
            None,
            Some(TokenContext {
                token_id: "token_selection".to_string(),
                owner_id: "user_1".to_string(),
                subject_binding: TokenSubjectBinding::Subject,
                scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
                    resource_selection: ResourceSelection::Selected,
                    selected_resources,
                    resource_permissions: HashMap::from([
                        ("document".to_string(), vec!["document:read".to_string()]),
                        ("project".to_string(), vec!["project:read".to_string()]),
                    ]),
                    org_permissions: HashMap::new(),
                })
                .expect("valid fine-grained scope"),
                expires_at: Some(2_000),
            }),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: Subject::user("user_1"),
            assignments: vec![assignment("multi_reader", Some("tenant"), None)],
            subject_parents: vec![parent("role", "multi_reader"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "project".to_string(),
            resource_id: "shared-id".to_string(),
            properties: json!({}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
    };

    let result = evaluator
        .evaluate_at(
            input(vec!["shared-id".to_string()]),
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(
        !result.decision,
        "a bare selected id cannot cross resource types"
    );
    assert_eq!(
        result.context.and_then(|context| context.reason),
        Some("token_resource_scope".to_string())
    );

    let typed_result = evaluator
        .evaluate_at(
            input(vec!["project:shared-id".to_string()]),
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("typed selection evaluation");
    assert!(
        typed_result.decision,
        "typed selected resources should allow the matching type"
    );
}

#[test]
fn given_org_permission_for_another_org_when_evaluating_then_token_ceiling_denies() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: Subject::user("user_1"),
            resource: Resource::new("organization", "org_denied")
                .with_properties(json!({"org_id": "org_denied"})),
            action: Action::new("manage"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &Subject::user("user_1"),
            None,
            None,
            Some(TokenContext {
                token_id: "token_org_ceiling".to_string(),
                owner_id: "user_1".to_string(),
                subject_binding: TokenSubjectBinding::Subject,
                scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
                    resource_selection: ResourceSelection::All,
                    selected_resources: Vec::new(),
                    resource_permissions: HashMap::from([(
                        "organization".to_string(),
                        vec!["organization:manage".to_string()],
                    )]),
                    org_permissions: HashMap::from([(
                        "org_allowed".to_string(),
                        vec!["organization:manage".to_string()],
                    )]),
                })
                .expect("valid fine-grained scope"),
                expires_at: Some(2_000),
            }),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: Subject::user("user_1"),
            assignments: vec![assignment("org_manager", Some("tenant"), None)],
            subject_parents: vec![parent("role", "org_manager"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org_denied".to_string(),
            properties: json!({"org_id": "org_denied"}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
    };

    let result = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(
        !result.decision,
        "org permission ceilings must bind to target org"
    );
}

#[test]
fn given_org_permission_for_target_org_when_evaluating_then_token_ceiling_allows() {
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let result = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: EvaluationRequest {
                    subject: Subject::user("user_1"),
                    resource: Resource::new("organization", "org_allowed")
                        .with_properties(json!({"org_id": "org_allowed"})),
                    action: Action::new("manage"),
                    context: None,
                    jwt_context: None,
                    session_context: None,
                    token_context: None,
                },
                trusted_context: TrustedAuthorizationContext::from_validated_parts(
                    &Subject::user("user_1"),
                    None,
                    None,
                    Some(TokenContext {
                        token_id: "token_org_allowed".to_string(),
                        owner_id: "user_1".to_string(),
                        subject_binding: TokenSubjectBinding::Subject,
                        scopes: TokenScopeConfig::fine_grained(FineGrainedScopes {
                            resource_selection: ResourceSelection::All,
                            selected_resources: Vec::new(),
                            resource_permissions: HashMap::from([(
                                "organization".to_string(),
                                vec!["organization:manage".to_string()],
                            )]),
                            org_permissions: HashMap::from([(
                                "org_allowed".to_string(),
                                vec!["organization:manage".to_string()],
                            )]),
                        })
                        .expect("valid fine-grained scope"),
                        expires_at: Some(2_000),
                    }),
                ),
                subject_access: SubjectAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    subject: Subject::user("user_1"),
                    assignments: vec![assignment("org_manager", Some("tenant"), None)],
                    subject_parents: vec![
                        parent("role", "org_manager"),
                        parent("tenant", "tenant_1"),
                    ],
                    resource_scopes: HashMap::new(),
                    fetched_at_ms: 1,
                },
                resource_access: ResourceAccessSnapshot {
                    tenant_id: "tenant_1".to_string(),
                    resource_type: "organization".to_string(),
                    resource_id: "org_allowed".to_string(),
                    properties: json!({"org_id": "org_allowed"}),
                    resource_parents: vec![parent("tenant", "tenant_1")],
                    fetched_at_ms: 1,
                },
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation");

    assert!(
        result.decision,
        "the target organization's ceiling should allow"
    );
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
        tenant_id: "tenant_1".to_string(),
        subject: request.subject.clone(),
        assignments: vec![assignment("reader", Some("tenant"), None)],
        subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
        resource_scopes: HashMap::new(),
        fetched_at_ms: 1,
    };
    let resource_access = ResourceAccessSnapshot {
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
        resource_parents: vec![parent("tenant", "tenant_1")],
        fetched_at_ms: 1,
    };

    let owned = evaluator
        .evaluate_at(
            LocalEvaluationInput {
                tenant_id: "tenant_1".to_string(),
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
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
                trusted_context: TrustedAuthorizationContext::default(),
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
        tenant_id: "tenant_1".to_string(),
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
        tenant_id: "tenant_1".to_string(),
        resource_type: "document".to_string(),
        resource_id: "doc_1".to_string(),
        properties: json!({}),
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
            trusted_context: TrustedAuthorizationContext::default(),
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
            trusted_context: TrustedAuthorizationContext::default(),
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
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: &subject_access,
                resource_access: &resource_access,
            });
            borrowed_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id: tenant_id.to_string(),
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: subject_access.clone(),
                resource_access: resource_access.clone(),
            });
            owned_ns += started.elapsed().as_nanos();
        } else {
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id: tenant_id.to_string(),
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
                subject_access: subject_access.clone(),
                resource_access: resource_access.clone(),
            });
            owned_ns += started.elapsed().as_nanos();
            let started = Instant::now();
            black_box(LocalEvaluationInput {
                tenant_id,
                request: request.clone(),
                trusted_context: TrustedAuthorizationContext::default(),
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
            tenant_id: "tenant_1".to_string(),
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
            tenant_id: "tenant_1".to_string(),
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            properties: json!({
                "org_id": "org_1",
                "classification": "internal"
            }),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms: 1,
        },
        request,
        trusted_context: TrustedAuthorizationContext::default(),
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

fn runtime_with_multi_resource_read_role() -> EvaluationRuntime {
    build_runtime(ConfigurationModel {
        version: 1,
        resource_types: vec![
            authz_types::ResourceType {
                id: "document".into(),
                name: "Document".into(),
                description: None,
                actions: vec![authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                }],
                context_schema: None,
            },
            authz_types::ResourceType {
                id: "project".into(),
                name: "Project".into(),
                description: None,
                actions: vec![authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                }],
                context_schema: None,
            },
        ],
        permissions: vec![
            authz_types::Permission {
                id: "document:read".into(),
                name: "Document read".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "read".into(),
                }],
                not_actions: vec![],
            },
            authz_types::Permission {
                id: "project:read".into(),
                name: "Project read".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "project".into(),
                    action_name: "read".into(),
                }],
                not_actions: vec![],
            },
        ],
        roles: vec![authz_types::Role {
            id: "multi_reader".into(),
            name: "Multi reader".into(),
            description: None,
            permissions: vec![
                authz_types::RolePermission {
                    permission_id: PermissionId::new("document:read").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                },
                authz_types::RolePermission {
                    permission_id: PermissionId::new("project:read").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                },
            ],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

fn runtime_with_read_write_scope_mapping() -> EvaluationRuntime {
    build_runtime(ConfigurationModel {
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
                id: "document:read".into(),
                name: "Document read".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "read".into(),
                }],
                not_actions: vec![],
            },
            authz_types::Permission {
                id: "document:write".into(),
                name: "Document write".into(),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "write".into(),
                }],
                not_actions: vec![],
            },
        ],
        roles: vec![],
        scope_mappings: vec![ScopeMappingEntry {
            scope: "document:read".to_string(),
            permissions: vec!["document:read".to_string(), "document:write".to_string()],
            includes: vec![],
        }],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

fn runtime_with_org_manage_role() -> EvaluationRuntime {
    build_runtime(ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "organization".into(),
            name: "Organization".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "manage".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "organization:manage".into(),
            name: "Organization manage".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "organization".into(),
                action_name: "manage".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "org_manager".into(),
            name: "Organization manager".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("organization:manage").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: permanent_assignment_policy(),
        }],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    })
}

fn build_runtime(config: ConfigurationModel) -> EvaluationRuntime {
    let config = config.into_validated().expect("valid config");
    let bundle = authz_cedar::compile_policy_bundle(&config, 1).expect("compiled bundle");
    EvaluationRuntime::build(config, &bundle).expect("runtime")
}

fn permanent_assignment_policy() -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec::try_new(AccessAssignmentMode::PermanentOrTemporary, None)
        .expect("permanent assignment policy")
}

#[test]
fn runtime_rejects_bundle_compiled_from_a_different_configuration() {
    let config_a = ConfigurationModel {
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
            name: "Document read".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("config A");
    let config_b = ConfigurationModel {
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
            id: "document:write".into(),
            name: "Document write".into(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "write".into(),
            }],
            not_actions: vec![],
        }],
        roles: vec![],
        scope_mappings: vec![],
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("config B");
    let bundle_b = authz_cedar::compile_policy_bundle(&config_b, 1).expect("bundle B");

    let error = EvaluationRuntime::build(config_a, &bundle_b)
        .expect_err("a bundle from another configuration must be rejected");
    assert!(matches!(error, crate::AuthzRuntimeError::Build));
}

#[test]
fn given_reader_snapshot_when_evaluating_via_convenience_api_then_allows_and_reports_permission() {
    // Given a current trusted snapshot for a tenant-wide reader assignment.
    let evaluator = LocalAuthzEvaluator::from_arc(Arc::new(runtime_with_read_role()));
    assert_eq!(evaluator.runtime().config().version, 1);

    // When the public convenience API evaluates the request.
    let response = evaluator
        .evaluate(reader_input("read", Utc::now().timestamp_millis()))
        .expect("trusted snapshots should evaluate");

    // Then the reader is allowed and the effective permission is identified.
    assert!(response.decision);
    assert_eq!(
        response
            .context
            .and_then(|context| context.effective_permission),
        Some("document:read".to_string())
    );
}

#[test]
fn given_trusted_subject_mismatch_when_resolving_permissions_then_denies_while_control_allows() {
    // Given a reader assignment and a request for user_1.
    let runtime = runtime_with_read_role();
    let input = reader_input("read", 1);
    let trusted_user = Subject::user("user_1");

    // When the trusted context matches the request subject.
    let matched = permissions_for_request_bits(
        &runtime,
        &input.subject_access.assignments,
        &input.request,
        &TrustedAuthorizationContext::from_validated_parts(&trusted_user, None, None, None),
        &input.request.subject,
        &input.subject_access.subject_parents,
    );

    // Then the control receives the declared document:read permission.
    assert_eq!(
        best_permission_for_action_with_bits(&runtime, "document", "read", &matched.permissions,),
        Some("document:read".to_string())
    );

    // And a separately validated context for another subject fails closed.
    let mismatched = permissions_for_request_bits(
        &runtime,
        &input.subject_access.assignments,
        &input.request,
        &TrustedAuthorizationContext::from_validated_parts(
            &Subject::user("user_2"),
            None,
            None,
            None,
        ),
        &input.request.subject,
        &input.subject_access.subject_parents,
    );
    assert_eq!(
        best_permission_for_action_with_bits(&runtime, "document", "read", &mismatched.permissions,),
        None
    );
}

#[test]
fn given_request_and_explicit_subject_differ_when_resolving_permissions_then_denies() {
    // Given a request for user_1 but a trusted role assignment for user_2.
    let runtime = runtime_with_read_role();
    let input = reader_input("read", 1);
    let explicit_subject = Subject::user("user_2");
    let assignments = vec![role_assignment("reader", "user_2", Some("tenant"), None)];
    let trusted_context =
        TrustedAuthorizationContext::from_validated_parts(&explicit_subject, None, None, None);

    // When the public permission helper receives the mismatched identities.
    let scoped = permissions_for_request_bits(
        &runtime,
        &assignments,
        &input.request,
        &trusted_context,
        &explicit_subject,
        &input.subject_access.subject_parents,
    );

    // Then the request subject cannot borrow another subject's grant.
    assert_eq!(
        best_permission_for_action_with_bits(&runtime, "document", "read", &scoped.permissions,),
        None
    );
}

#[test]
fn given_same_subject_id_with_different_types_when_resolving_permissions_then_denies() {
    // Given a User request and a Role credential that share the same id.
    let runtime = runtime_with_read_role();
    let request_subject = Subject::user("shared");
    let explicit_subject = Subject::role("shared");
    let request = EvaluationRequest {
        subject: request_subject.clone(),
        resource: Resource::new("document", "doc_1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let assignments = vec![role_assignment("reader", "shared", Some("tenant"), None)];

    // When the same grant is evaluated with the matching User identity.
    let matching_user_context =
        TrustedAuthorizationContext::from_validated_parts(&request_subject, None, None, None);
    let matching = permissions_for_request_bits(
        &runtime,
        &assignments,
        &request,
        &matching_user_context,
        &request_subject,
        &[],
    );

    // Then the matching User identity is grant-capable.
    assert_eq!(
        best_permission_for_action_with_bits(&runtime, "document", "read", &matching.permissions,),
        Some("document:read".to_string())
    );

    // Given the same id presented as a different SubjectType.
    let trusted_context =
        TrustedAuthorizationContext::from_validated_parts(&explicit_subject, None, None, None);

    // When the public permission helper receives the same id with a different
    // type.
    let scoped = permissions_for_request_bits(
        &runtime,
        &assignments,
        &request,
        &trusted_context,
        &explicit_subject,
        &[],
    );

    // Then an identity type collision cannot borrow the Role's grant.
    assert_eq!(
        best_permission_for_action_with_bits(&runtime, "document", "read", &scoped.permissions,),
        None
    );
}

#[test]
fn given_declared_read_and_unknown_delete_when_evaluating_then_only_read_is_allowed() {
    // Given a reader runtime and deterministic snapshots.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    // When the declared action and an unknown action are evaluated through the
    // runtime boundary.
    let read = evaluator
        .evaluate_at(reader_input("read", 1), now)
        .expect("declared action should evaluate");
    let delete = evaluator
        .evaluate_at(reader_input("delete", 1), now)
        .expect("unknown action should produce a denial response");

    // Then the declared action is grantable and the unknown action is denied.
    assert!(read.decision);
    assert_eq!(
        read.context
            .and_then(|context| context.effective_permission),
        Some("document:read".to_string())
    );
    assert!(!delete.decision);
    assert_eq!(
        delete.context.and_then(|context| context.reason),
        Some("no_policy_allow".to_string())
    );
}

#[test]
fn given_unknown_role_assignment_when_evaluating_then_known_role_still_grants() {
    // Given a valid reader assignment alongside an unknown role identifier.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let mut input = reader_input("read", 1);
    input.subject_access.assignments = vec![
        assignment("unknown_role", Some("tenant"), None),
        assignment("reader", Some("tenant"), None),
    ];
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");

    // When the public local evaluator resolves the assignment snapshot.
    let response = evaluator.evaluate_at(input, now).expect("evaluation");

    // Then an unknown role is ignored without suppressing the known grant.
    assert!(response.decision);
    assert_eq!(
        response
            .context
            .and_then(|context| context.effective_permission),
        Some("document:read".to_string())
    );
}

#[test]
fn given_tenant_assignment_without_principal_when_evaluating_then_grants_to_request_subject() {
    // Given a tenant-wide assignment intentionally shared by every subject.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let mut input = reader_input("read", 1);
    input.subject_access.assignments = vec![EffectiveRoleAssignment {
        principal_id: None,
        role_id: "reader".to_string(),
        scope_type: Some("tenant".to_string()),
        scope_id: None,
        expires_at: None,
    }];

    // When the public local evaluator resolves this assignment.
    let response = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("shared assignment evaluation");

    // Then a principal-less tenant assignment remains grant-capable.
    assert!(response.decision);
}

#[test]
fn given_trusted_jwt_role_scopes_when_evaluating_then_only_applicable_scopes_grant() {
    // Given one evaluator and JWT roles covering every supported scope shape.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let cases = vec![
        (
            "unknown role",
            RoleAssignment {
                role_id: "unknown_role".to_string(),
                scope: RoleScope::Global,
            },
            false,
        ),
        (
            "matching org",
            RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Org {
                    org_id: "org_1".to_string(),
                },
            },
            true,
        ),
        (
            "other org",
            RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Org {
                    org_id: "org_2".to_string(),
                },
            },
            false,
        ),
        (
            "matching resource",
            RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: "document".to_string(),
                    resource_id: "doc_1".to_string(),
                },
            },
            true,
        ),
        (
            "other resource",
            RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: "document".to_string(),
                    resource_id: "doc_2".to_string(),
                },
            },
            false,
        ),
        (
            "group role",
            RoleAssignment {
                role_id: "reader".to_string(),
                scope: RoleScope::Group {
                    group_id: "group_1".to_string(),
                },
            },
            false,
        ),
    ];

    // When each trusted role is evaluated against the authoritative org.
    for (label, role, expected) in cases {
        let mut input = reader_input("read", 1);
        input.subject_access.assignments.clear();
        input.subject_access.subject_parents.clear();
        input.resource_access.properties = json!({"org_id": "org_1"});
        let subject = input.request.subject.clone();
        let trusted_context = TrustedAuthorizationContext::from_validated_parts(
            &subject,
            Some(JwtContext::complete(Vec::new(), Vec::new(), vec![role])),
            None,
            None,
        );
        input.trusted_context = trusted_context;

        let response = evaluator
            .evaluate_at(
                input,
                Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
            )
            .unwrap_or_else(|_| panic!("{label} evaluation failed"));

        // Then only the role scope that covers this resource can grant.
        assert_eq!(response.decision, expected, "case: {label}");
    }
}

#[test]
fn given_unknown_resource_type_when_evaluating_public_read_then_denies() {
    // Given a request whose resource type is absent from the policy catalog.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role());
    let mut input = reader_input("read", 1);
    input.request.resource = Resource::new("unknown", "unknown_1");
    input.subject_access.assignments.clear();
    input.subject_access.subject_parents.clear();
    input.resource_access.resource_type = "unknown".to_string();
    input.resource_access.resource_id = "unknown_1".to_string();
    input.resource_access.resource_parents.clear();

    // When the local evaluator handles the undeclared public-read request.
    let response = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("unknown resource is a normal denial");

    // Then absence from the catalog fails closed even for a read action.
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("no_policy_allow".to_string())
    );
}

#[test]
fn given_mixed_batch_with_unknown_action_when_evaluating_then_preliminary_denial_is_preserved() {
    // Given one grantable action and one unknown action in the same batch.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_batch_actions(2));
    let mut input = reader_input("action_0", 1);
    input.subject_access.assignments = vec![assignment("batch_reader", Some("tenant"), None)];
    input.subject_access.subject_parents = vec![parent("role", "batch_reader")];
    let actions = vec![Action::new("action_0"), Action::new("unknown")];

    // When the public batch evaluator prepares both actions together.
    let responses = evaluator
        .evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: input.tenant_id,
                request: input.request,
                trusted_context: input.trusted_context,
                actions: &actions,
                subject_access: input.subject_access,
                resource_access: input.resource_access,
            },
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("mixed batch evaluation");

    // Then Cedar evaluates the grant while the preliminary denial stays denied.
    assert_eq!(responses.len(), 2);
    assert!(responses[0].decision);
    assert!(!responses[1].decision);
    assert_eq!(
        responses[1]
            .context
            .as_ref()
            .and_then(|context| context.reason.as_deref()),
        Some("no_policy_allow")
    );
}

#[test]
fn given_read_permission_requiring_mfa_when_evaluating_without_session_then_challenges() {
    // Given a reader policy whose read action requires a multi-factor step-up.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_read_role_requiring_mfa());

    // When the public evaluator receives no trusted session context.
    let response = evaluator
        .evaluate_at(
            reader_input("read", 1),
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("step-up is a normal response");

    // Then the grant is held behind an explicit MFA challenge.
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("step_up:mfa".to_string())
    );
    assert_eq!(
        response
            .challenge
            .as_ref()
            .map(|challenge| challenge.triggered_by_rule.as_str()),
        Some("require_mfa")
    );
}

#[test]
fn given_resource_scoped_assignment_when_evaluating_then_only_matching_snapshot_scope_grants() {
    // Given a resource-scoped role and independently evaluated candidate
    // assignments.
    let evaluator =
        LocalAuthzEvaluator::new(runtime_with_read_role_scope(Scope::resource("document")));
    let evaluate_assignment = |scope_type, scope_id| {
        let mut input = reader_input("read", 1);
        input.subject_access.assignments = vec![assignment("reader", scope_type, scope_id)];
        input.subject_access.subject_parents = vec![parent("role", "reader")];

        evaluator
            .evaluate_at(
                input,
                Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
            )
            .expect("resource-scoped evaluation")
    };

    // When each malformed or unrelated scope is evaluated independently.
    let bare_resource = evaluate_assignment(Some("resource"), Some("doc_1"));
    let wrong_resource_type = evaluate_assignment(Some("resource:project"), Some("doc_1"));
    let missing_resource_id = evaluate_assignment(Some("resource:document"), None);

    // Then none of the malformed or unrelated scopes can grant.
    assert!(!bare_resource.decision);
    assert!(!wrong_resource_type.decision);
    assert!(!missing_resource_id.decision);

    // And the exact typed resource:document/doc_1 scope is the only allow.
    let exact_resource = evaluate_assignment(Some("resource:document"), Some("doc_1"));
    assert!(exact_resource.decision);
    assert_eq!(
        exact_resource
            .context
            .and_then(|context| context.effective_permission),
        Some("document:read".to_string())
    );
}

#[test]
fn given_subject_token_owner_has_target_org_assignment_when_evaluating_then_allows() {
    // Given a subject-bound token and an assignment scoped to its target org.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let subject = Subject::user("user_1");
    let input = LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: subject.clone(),
            resource: Resource::new("organization", "org_allowed")
                .with_properties(json!({"org_id": "org_allowed"})),
            action: Action::new("manage"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::from_validated_parts(
            &subject,
            None,
            None,
            Some(TokenContext::new(
                "token_owner_org_allow".to_string(),
                "user_1".to_string(),
                TokenScopeConfig::full_access()
                    .with_org("org_allowed".to_string())
                    .expect("valid organization binding"),
            )),
        ),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject: subject.clone(),
            assignments: vec![assignment("org_manager", Some("org"), Some("org_allowed"))],
            subject_parents: vec![parent("role", "org_manager"), parent("org", "org_allowed")],
            resource_scopes: HashMap::new(),
            fetched_at_ms: 1,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "organization".to_string(),
            resource_id: "org_allowed".to_string(),
            properties: json!({"org_id": "org_allowed"}),
            resource_parents: vec![],
            fetched_at_ms: 1,
        },
    };

    // When evaluating at the supplied clock.
    let response = evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("matching token owner org is a normal evaluation");

    // Then the owner-org check and token ceiling both permit the grant.
    assert!(response.decision);
}

#[test]
fn given_delegated_org_token_when_target_org_matches_then_allows_without_owner_assignment() {
    // Given a delegated service token whose owner is not the evaluated subject
    // and has no corresponding organization assignment in the subject snapshot.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_org_manage_role());
    let subject = Subject::user("user_1");
    let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
    let evaluate_for_org = |org_id: &str| {
        evaluator
            .evaluate_at(
                LocalEvaluationInput {
                    tenant_id: "tenant_1".to_string(),
                    request: EvaluationRequest {
                        subject: subject.clone(),
                        resource: Resource::new("organization", org_id)
                            .with_properties(json!({"org_id": org_id})),
                        action: Action::new("manage"),
                        context: None,
                        jwt_context: None,
                        session_context: None,
                        token_context: None,
                    },
                    trusted_context: TrustedAuthorizationContext::from_validated_parts(
                        &subject,
                        None,
                        None,
                        Some(TokenContext::delegated(
                            "token_service_org".to_string(),
                            "runtime_caller".to_string(),
                            TokenScopeConfig::full_access()
                                .with_org("org_allowed".to_string())
                                .expect("valid organization binding"),
                        )),
                    ),
                    subject_access: SubjectAccessSnapshot {
                        tenant_id: "tenant_1".to_string(),
                        subject: subject.clone(),
                        assignments: vec![assignment("org_manager", Some("tenant"), None)],
                        subject_parents: vec![
                            parent("role", "org_manager"),
                            parent("tenant", "tenant_1"),
                        ],
                        resource_scopes: HashMap::new(),
                        fetched_at_ms: 1,
                    },
                    resource_access: ResourceAccessSnapshot {
                        tenant_id: "tenant_1".to_string(),
                        resource_type: "organization".to_string(),
                        resource_id: org_id.to_string(),
                        properties: json!({"org_id": org_id}),
                        resource_parents: vec![parent("tenant", "tenant_1")],
                        fetched_at_ms: 1,
                    },
                },
                now,
            )
            .expect("delegated token evaluation")
    };

    // When the delegated token evaluates the organization named by its scope.
    let allowed = evaluate_for_org("org_allowed");

    // Then the service credential's organization binding is sufficient even
    // though the token owner is absent from the evaluated subject snapshot.
    assert!(allowed.decision);
    assert_eq!(
        allowed
            .context
            .and_then(|context| context.effective_permission),
        Some("organization:manage".to_string())
    );

    // When the same delegated token targets a different organization.
    let denied = evaluate_for_org("org_denied");

    // Then the token ceiling fails closed before Cedar can grant access.
    assert!(!denied.decision);
    assert_eq!(
        denied.context.and_then(|context| context.reason),
        Some("token_org_mismatch".to_string())
    );
}

#[test]
fn given_role_not_action_for_read_when_evaluating_then_denies_before_cedar() {
    // Given a role whose direct not_actions explicitly deny document:read.
    let evaluator = LocalAuthzEvaluator::new(runtime_with_role_read_deny());

    // When the assigned role evaluates the denied action.
    let response = evaluator
        .evaluate_at(
            reader_input("read", 1),
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("role denial is a normal response");

    // Then the role-level deny wins and is surfaced as deny_matched.
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("deny_matched".to_string())
    );
}

fn reader_input(action: &str, fetched_at_ms: i64) -> LocalEvaluationInput {
    let subject = Subject::user("user_1");
    LocalEvaluationInput {
        tenant_id: "tenant_1".to_string(),
        request: EvaluationRequest {
            subject: subject.clone(),
            resource: Resource::new("document", "doc_1"),
            action: Action::new(action),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        },
        trusted_context: TrustedAuthorizationContext::default(),
        subject_access: SubjectAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            subject,
            assignments: vec![assignment("reader", Some("tenant"), None)],
            subject_parents: vec![parent("role", "reader"), parent("tenant", "tenant_1")],
            resource_scopes: HashMap::new(),
            fetched_at_ms,
        },
        resource_access: ResourceAccessSnapshot {
            tenant_id: "tenant_1".to_string(),
            resource_type: "document".to_string(),
            resource_id: "doc_1".to_string(),
            properties: json!({}),
            resource_parents: vec![parent("tenant", "tenant_1")],
            fetched_at_ms,
        },
    }
}

fn assignment(
    role_id: &str,
    scope_type: Option<&str>,
    scope_id: Option<&str>,
) -> EffectiveRoleAssignment {
    role_assignment(role_id, "user_1", scope_type, scope_id)
}

fn role_assignment(
    role_id: &str,
    principal_id: &str,
    scope_type: Option<&str>,
    scope_id: Option<&str>,
) -> EffectiveRoleAssignment {
    EffectiveRoleAssignment {
        principal_id: Some(principal_id.to_string()),
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

#[test]
fn given_direct_role_actions_when_full_access_credentials_evaluate_then_subject_authority_is_preserved()
 {
    let mut config = runtime_with_role_read_deny().config.clone().into_inner();
    config.permissions.clear();
    config.roles[0].permissions.clear();
    config.roles[0].not_actions.clear();
    config.roles[0].actions = vec![RoleActionRef {
        resource_type: "document".into(),
        action_name: "read".into(),
        scopes: vec![Scope::Tenant],
        limit: None,
    }];
    let evaluator = LocalAuthzEvaluator::new(build_runtime(config));
    let full = TokenContext::new(
        "full_token".into(),
        "user_1".into(),
        TokenScopeConfig::full_access(),
    );
    let delegated = TokenContext::delegated(
        "runtime_token".into(),
        "runtime_owner".into(),
        TokenScopeConfig::full_access(),
    );
    let restricted = TokenContext::new(
        "restricted_token".into(),
        "user_1".into(),
        TokenScopeConfig::with_scopes(vec!["unmapped".into()]).expect("scope"),
    );
    for (token, expected) in [
        (None, true),
        (Some(full.clone()), true),
        (Some(delegated), true),
        (Some(restricted), false),
        (
            Some(TokenContext {
                owner_id: "other_user".into(),
                ..full.clone()
            }),
            false,
        ),
        (Some(full.with_expiration(Some(999))), false),
    ] {
        let response = evaluate_direct_reader(&evaluator, token, true);
        assert_eq!(response.decision, expected, "{:?}", response.context);
    }
    assert!(
        !evaluate_direct_reader(
            &evaluator,
            Some(TokenContext::delegated(
                "runtime_token".into(),
                "runtime_owner".into(),
                TokenScopeConfig::full_access()
            )),
            false
        )
        .decision
    );
    let denying = LocalAuthzEvaluator::new(runtime_with_role_read_deny());
    assert!(
        !evaluate_direct_reader(
            &denying,
            Some(TokenContext::new(
                "full_token".into(),
                "user_1".into(),
                TokenScopeConfig::full_access()
            )),
            true
        )
        .decision
    );
}

fn evaluate_direct_reader(
    evaluator: &LocalAuthzEvaluator,
    token: Option<TokenContext>,
    assigned: bool,
) -> authz_types::EvaluationResponse {
    let mut input = reader_input("read", 1);
    if !assigned {
        input.subject_access.assignments.clear();
        input.subject_access.subject_parents.clear();
    }
    input.trusted_context = TrustedAuthorizationContext::from_validated_parts(
        &input.request.subject,
        None,
        None,
        token,
    );
    evaluator
        .evaluate_at(
            input,
            Utc.timestamp_opt(1_000, 0).single().expect("timestamp"),
        )
        .expect("evaluation")
}
