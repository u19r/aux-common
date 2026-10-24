use std::{collections::HashMap, sync::Arc, time::Duration};

use authz_types::{
    AccessAssignmentMode, AccessAssignmentPolicySpec, Action, ConfigurationModel, Context,
    EvaluationRequest, JwtContext, PermissionActionRef, PermissionId, Resource, RoleAssignment,
    RoleScope, Scope, ScopeMappingEntry, Subject,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

use super::{
    EnrichedCedarRequest, ParentRef, ResourceAccessSnapshot, SnapshotFreshnessPolicy,
    SubjectAccessSnapshot, build_subject_parent_template, enrich_request_with_snapshots,
    enrich_request_with_snapshots_at,
};
use crate::{
    AuthzRuntimeError, EffectiveRoleAssignment, EvaluationRuntime, LocalAuthzEvaluator,
    LocalEvaluationInput, TrustedAuthorizationContext,
};

const TENANT_ID: &str = "tenant_1";
const SUBJECT_ID: &str = "user_1";
const RESOURCE_TYPE: &str = "document";
const RESOURCE_ID: &str = "doc_1";

fn request() -> EvaluationRequest {
    EvaluationRequest {
        subject: Subject::user(SUBJECT_ID),
        resource: Resource::new(RESOURCE_TYPE, RESOURCE_ID),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    }
}

fn subject_snapshot(subject: Subject, fetched_at_ms: i64) -> SubjectAccessSnapshot {
    SubjectAccessSnapshot {
        tenant_id: TENANT_ID.to_string(),
        subject,
        assignments: Vec::new(),
        subject_parents: Vec::new(),
        resource_scopes: HashMap::new(),
        fetched_at_ms,
    }
}

fn resource_snapshot(
    properties: Value,
    resource_parents: Vec<ParentRef>,
    fetched_at_ms: i64,
) -> ResourceAccessSnapshot {
    ResourceAccessSnapshot {
        tenant_id: TENANT_ID.to_string(),
        resource_type: RESOURCE_TYPE.to_string(),
        resource_id: RESOURCE_ID.to_string(),
        properties,
        resource_parents,
        fetched_at_ms,
    }
}

fn parent(ref_type: &str, id: &str) -> ParentRef {
    ParentRef {
        ref_type: ref_type.to_string(),
        id: id.to_string(),
    }
}

fn assignment(
    role_id: &str,
    scope_type: Option<&str>,
    scope_id: Option<&str>,
) -> EffectiveRoleAssignment {
    EffectiveRoleAssignment {
        principal_id: None,
        role_id: role_id.to_string(),
        scope_type: scope_type.map(str::to_string),
        scope_id: scope_id.map(str::to_string),
        expires_at: None,
    }
}

fn timestamp(milliseconds: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(milliseconds)
        .single()
        .expect("test timestamp must be representable")
}

fn enriched_at(
    request: EvaluationRequest,
    trusted_context: &TrustedAuthorizationContext,
    subject_access: &SubjectAccessSnapshot,
    resource_access: &ResourceAccessSnapshot,
    now: DateTime<Utc>,
) -> Result<EnrichedCedarRequest, AuthzRuntimeError> {
    enrich_request_with_snapshots_at(
        TENANT_ID,
        request,
        trusted_context,
        subject_access,
        resource_access,
        now,
        SnapshotFreshnessPolicy::default(),
    )
}

fn runtime_with_org_read_role() -> EvaluationRuntime {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: RESOURCE_TYPE.to_string(),
            name: "Document".to_string(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".to_string(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:read".to_string(),
            name: "Document reader".to_string(),
            description: None,
            actions: vec![PermissionActionRef {
                resource_type: RESOURCE_TYPE.to_string(),
                action_name: "read".to_string(),
            }],
            not_actions: vec![],
        }],
        roles: vec![authz_types::Role {
            id: "reader".to_string(),
            name: "Reader".to_string(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:read").expect("permission id"),
                scopes: vec![Scope::Org],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: AccessAssignmentPolicySpec::try_new(
                AccessAssignmentMode::PermanentOrTemporary,
                None,
            )
            .expect("assignment policy"),
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
    };
    let validated = config.into_validated().expect("valid test config");
    let bundle = authz_cedar::compile_policy_bundle(&validated, 1).expect("compiled bundle");
    EvaluationRuntime::build(validated, &bundle).expect("runtime")
}

#[test]
fn given_default_snapshot_policy_when_reading_limits_then_reports_five_minute_age_and_thirty_second_skew()
 {
    // Given the public default freshness contract.
    let policy = SnapshotFreshnessPolicy::default();

    // When callers inspect its limits.
    // Then the replay and clock-skew windows are explicit and bounded.
    assert_eq!(policy.max_age(), Duration::from_secs(300));
    assert_eq!(policy.max_future_skew(), Duration::from_secs(30));
}

#[test]
fn given_group_and_malformed_scopes_when_building_parent_template_then_skips_unusable_scopes() {
    // Given role assignments covering a supported group, a resource without an
    // id, a resource without a type, and an unknown scope kind.
    let assignments = vec![
        assignment("group_reader", Some("group"), Some("group_1")),
        assignment("resource_without_id", Some("resource:document"), None),
        assignment("resource_without_type", Some("resource"), Some("ignored")),
        assignment("unknown_scope", Some("workspace"), Some("ignored")),
    ];

    // When converting assignments to Cedar parent and scope data.
    let template = build_subject_parent_template(&assignments, &[], TENANT_ID);

    // Then only the supported group relationship and role identities survive;
    // malformed scope records fail closed without inventing a resource scope.
    assert!(template.parents.contains(&parent("group", "group_1")));
    assert!(template.parents.contains(&parent("role", "group_reader")));
    assert!(
        template
            .parents
            .contains(&parent("role", "resource_without_id"))
    );
    assert!(
        template
            .parents
            .contains(&parent("role", "resource_without_type"))
    );
    assert!(template.parents.contains(&parent("role", "unknown_scope")));
    assert_eq!(template.resource_scopes, HashMap::new());
}

#[test]
fn given_fresh_snapshots_and_wire_properties_when_using_wall_clock_wrapper_then_uses_snapshot_authority()
 {
    // Given caller-owned properties/context and a separately validated JWT.
    let subject = Subject::user(SUBJECT_ID).with_properties(json!({"department": "engineering"}));
    let trusted_jwt = JwtContext::complete(
        Vec::new(),
        Vec::new(),
        vec![RoleAssignment {
            role_id: "global_reader".to_string(),
            scope: RoleScope::Global,
        }],
    );
    let mut wire_request = request();
    wire_request.subject = subject
        .clone()
        .with_properties(json!({"department": "caller"}));
    wire_request.resource = Resource::new(RESOURCE_TYPE, RESOURCE_ID).with_properties(json!({
        "org_id": "caller_org",
        "is_public": true,
    }));
    wire_request.context = Some(Context::new(json!({"request_id": "req_1"})));
    wire_request.jwt_context = Some(JwtContext::default());
    let trusted_context = TrustedAuthorizationContext::from_validated_parts(
        &subject,
        Some(trusted_jwt.clone()),
        None,
        None,
    );
    let fetched_at_ms = Utc::now().timestamp_millis();
    let subject_access = subject_snapshot(subject, fetched_at_ms);
    let resource_access = resource_snapshot(
        json!({"org_id": "org_1", "is_public": false}),
        vec![parent("org", "org_1")],
        fetched_at_ms,
    );

    // When enriching through the public wall-clock convenience boundary.
    let enriched = enrich_request_with_snapshots(
        TENANT_ID,
        wire_request,
        &trusted_context,
        &subject_access,
        &resource_access,
    )
    .expect("fresh snapshots should enrich");

    // Then only snapshot properties and validated credentials reach the result,
    // while benign request context remains available to the caller.
    assert_eq!(
        enriched.request.subject.properties,
        Some(json!({"department": "engineering"}))
    );
    assert_eq!(
        enriched.request.resource.properties,
        Some(json!({"org_id": "org_1", "is_public": false}))
    );
    assert_eq!(
        enriched.request.context.map(|context| context.attributes),
        Some(json!({
            "request_id": "req_1"
        }))
    );
    assert_eq!(enriched.request.jwt_context, Some(trusted_jwt));
    assert!(
        enriched
            .subject_parents
            .contains(&parent("role", "global_reader"))
    );
    assert!(
        enriched
            .subject_parents
            .contains(&parent("tenant", TENANT_ID))
    );
}

#[test]
fn given_stale_resource_snapshot_when_enriching_then_rejects_resource_provenance() {
    // Given a fresh subject snapshot and a resource snapshot older than the
    // default replay window.
    let now = timestamp(600_000);
    let subject_access = subject_snapshot(Subject::user(SUBJECT_ID), 600_000);
    let resource_access = resource_snapshot(json!({}), Vec::new(), 1);

    // When the runtime checks snapshot freshness.
    let error = enriched_at(
        request(),
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        now,
    )
    .expect_err("stale resource snapshots must fail closed");

    // Then the rejected snapshot is identified without evaluating its data.
    assert!(matches!(
        error,
        AuthzRuntimeError::SnapshotStale {
            snapshot: "resource"
        }
    ));
}

#[test]
fn given_future_subject_snapshot_when_enriching_then_rejects_subject_provenance() {
    // Given a resource snapshot at the current clock and a subject snapshot
    // beyond the allowed future skew.
    let now = timestamp(100_000);
    let subject_access = subject_snapshot(Subject::user(SUBJECT_ID), 130_001);
    let resource_access = resource_snapshot(json!({}), Vec::new(), 100_000);

    // When the runtime checks snapshot freshness.
    let error = enriched_at(
        request(),
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        now,
    )
    .expect_err("future subject snapshots must fail closed");

    // Then a future-dated identity snapshot is rejected before enrichment.
    assert!(matches!(
        error,
        AuthzRuntimeError::SnapshotTimestampInvalid {
            snapshot: "subject"
        }
    ));
}

#[test]
fn given_cross_tenant_snapshots_when_enriching_then_rejects_tenant_provenance() {
    // Given snapshots fetched for another tenant but otherwise matching the
    // request's subject and resource identities.
    let mut subject_access = subject_snapshot(Subject::user(SUBJECT_ID), 1_000);
    subject_access.tenant_id = "tenant_2".to_string();
    let mut resource_access = resource_snapshot(json!({}), Vec::new(), 1_000);
    resource_access.tenant_id = "tenant_2".to_string();

    // When evaluating under tenant_1.
    let error = enriched_at(
        request(),
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        timestamp(1_000),
    )
    .expect_err("cross-tenant snapshots must fail closed");

    // Then no access data from tenant_2 can enter tenant_1's decision.
    assert!(matches!(error, AuthzRuntimeError::TenantSnapshotMismatch));
}

#[test]
fn given_mismatched_trusted_subject_when_enriching_then_rejects_before_snapshot_use() {
    // Given a validated context for another subject and matching snapshots for
    // the request subject.
    let subject = Subject::user(SUBJECT_ID);
    let trusted_context = TrustedAuthorizationContext::from_validated_parts(
        &Subject::user("user_2"),
        None,
        None,
        None,
    );
    let subject_access = subject_snapshot(subject, 1_000);
    let resource_access = resource_snapshot(json!({}), Vec::new(), 1_000);

    // When the trusted context is paired with the request.
    let error = enriched_at(
        request(),
        &trusted_context,
        &subject_access,
        &resource_access,
        timestamp(1_000),
    )
    .expect_err("trusted subject mismatch must fail closed");

    // Then untrusted credentials cannot be paired with another identity.
    assert!(matches!(
        error,
        AuthzRuntimeError::TrustedContextSubjectMismatch
    ));
}

#[test]
fn given_trusted_jwt_with_mixed_scopes_when_enriching_then_adds_only_applicable_roles() {
    // Given trusted roles for the current organization/resource plus off-scope
    // organization, resource, and group roles.
    let subject = Subject::user(SUBJECT_ID);
    let trusted_jwt = JwtContext::complete(
        Vec::new(),
        Vec::new(),
        vec![
            RoleAssignment {
                role_id: "global_reader".to_string(),
                scope: RoleScope::Global,
            },
            RoleAssignment {
                role_id: "org_reader".to_string(),
                scope: RoleScope::Org {
                    org_id: "org_1".to_string(),
                },
            },
            RoleAssignment {
                role_id: "other_org_reader".to_string(),
                scope: RoleScope::Org {
                    org_id: "org_2".to_string(),
                },
            },
            RoleAssignment {
                role_id: "resource_reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: RESOURCE_TYPE.to_string(),
                    resource_id: RESOURCE_ID.to_string(),
                },
            },
            RoleAssignment {
                role_id: "other_resource_reader".to_string(),
                scope: RoleScope::Resource {
                    resource_type: RESOURCE_TYPE.to_string(),
                    resource_id: "doc_2".to_string(),
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
    let trusted_context =
        TrustedAuthorizationContext::from_validated_parts(&subject, Some(trusted_jwt), None, None);
    let subject_access = subject_snapshot(subject, 1_000);
    let resource_access = resource_snapshot(json!({"org_id": "org_1"}), Vec::new(), 1_000);

    // When enriching against the authoritative resource snapshot.
    let enriched = enriched_at(
        request(),
        &trusted_context,
        &subject_access,
        &resource_access,
        timestamp(1_000),
    )
    .expect("trusted role scopes should be filtered");

    // Then only global, matching organization, and matching resource roles are
    // represented as Cedar parents.
    for role_id in ["global_reader", "org_reader", "resource_reader"] {
        assert!(enriched.subject_parents.contains(&parent("role", role_id)));
    }
    for role_id in ["other_org_reader", "other_resource_reader", "group_reader"] {
        assert!(!enriched.subject_parents.contains(&parent("role", role_id)));
    }
    assert!(enriched.subject_parents.contains(&parent("org", "org_1")));
    assert!(
        enriched
            .subject_parents
            .contains(&parent("tenant", TENANT_ID))
    );
}

#[test]
fn given_non_object_resource_snapshot_properties_when_enriching_then_does_not_inject_parent_data() {
    // Given a trusted resource snapshot whose attribute payload is not an
    // object, plus a caller attempt to supply forged properties.
    let mut wire_request = request();
    wire_request.resource = Resource::new(RESOURCE_TYPE, RESOURCE_ID)
        .with_properties(json!({"org_id": "caller_org", "is_public": true}));
    let subject_access = subject_snapshot(Subject::user(SUBJECT_ID), 1_000);
    let resource_access =
        resource_snapshot(json!("trusted-scalar"), vec![parent("org", "org_1")], 1_000);

    // When enriching with the snapshot as the only resource authority.
    let enriched = enriched_at(
        wire_request,
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        timestamp(1_000),
    )
    .expect("non-object snapshots remain a trusted payload for Cedar normalization");

    // Then caller properties are discarded and parent injection does not
    // fabricate an object around malformed trusted data.
    assert_eq!(
        enriched.request.resource.properties,
        Some(json!("trusted-scalar"))
    );
}

#[test]
fn given_conflicting_resource_org_parents_when_enriching_then_rejects_before_cedar() {
    // Given a resource snapshot whose relationship graph names two different
    // organizations, including a case-variant parent type, and carries no
    // independent org property.
    let subject_access = subject_snapshot(Subject::user(SUBJECT_ID), 1_000);
    let resource_access = resource_snapshot(
        json!({}),
        vec![parent("org", "org_2"), parent("ORG", "org_1")],
        1_000,
    );

    // When the public enrichment boundary validates resource ancestry.
    let error = enriched_at(
        request(),
        &TrustedAuthorizationContext::default(),
        &subject_access,
        &resource_access,
        timestamp(1_000),
    )
    .expect_err("conflicting relationships must be rejected before Cedar");

    // Then neither ambiguous organization parent can reach policy evaluation.
    assert!(matches!(
        error,
        AuthzRuntimeError::ConflictingResourceOrgParents
    ));
}

#[test]
fn given_conflicting_resource_org_ancestry_when_evaluating_then_cannot_grant_org_policy() {
    // Given an org-scoped reader whose target org property would otherwise
    // satisfy the policy, but whose resource ancestry names a second org.
    let evaluator = LocalAuthzEvaluator::from_arc_with_snapshot_freshness(
        Arc::new(runtime_with_org_read_role()),
        SnapshotFreshnessPolicy::for_tests(),
    );
    let subject = Subject::user(SUBJECT_ID);
    let mut subject_access = subject_snapshot(subject, 1_000);
    subject_access.assignments = vec![assignment("reader", Some("org"), Some("org_1"))];
    subject_access.subject_parents = vec![parent("role", "reader"), parent("org", "org_1")];
    let input = LocalEvaluationInput {
        tenant_id: TENANT_ID.to_string(),
        request: request(),
        trusted_context: TrustedAuthorizationContext::default(),
        subject_access,
        resource_access: resource_snapshot(
            json!({"org_id": "org_1"}),
            vec![parent("ORG", "org_1"), parent("org", "org_2")],
            1_000,
        ),
    };

    // When the public evaluator evaluates the ancestry-backed request.
    // The vulnerable implementation sorts this case with org_1 first, so its
    // org-scoped policy would incorrectly grant before the boundary check.
    let error = evaluator
        .evaluate_at(input, timestamp(1_000))
        .expect_err("conflicting resource ancestry must fail before policy evaluation");

    // Then an org-scoped policy cannot be granted from an ambiguous resource
    // graph, even when one parent matches the resource org property.
    assert!(matches!(
        error,
        AuthzRuntimeError::ConflictingResourceOrgParents
    ));
}
