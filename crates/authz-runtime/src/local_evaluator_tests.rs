use std::collections::{HashMap, HashSet};

use authz_types::{Action, Context, EvaluationRequest, Resource, Subject};
use chrono::{TimeZone, Utc};
use serde_json::json;

use crate::{
    EffectiveRoleAssignment, ParentRef, ResourceAccessSnapshot, SubjectAccessSnapshot,
    build_subject_parent_template, enrich_request_with_snapshots, inject_internal_context,
};

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
