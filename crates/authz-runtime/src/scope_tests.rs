use crate::{EffectiveRoleAssignment, ScopeKind, classify_scope, role_assignment_covers_resource};

#[test]
fn classify_scope_supports_known_values_case_insensitively() {
    assert_eq!(classify_scope("tenant"), ScopeKind::Tenant);
    assert_eq!(classify_scope("ORG"), ScopeKind::Org);
    assert_eq!(classify_scope(" Group "), ScopeKind::Group);
    assert_eq!(
        classify_scope("RESOURCE:Document"),
        ScopeKind::Resource {
            resource_type: Some("Document"),
        }
    );
    assert_eq!(
        classify_scope("resource"),
        ScopeKind::Resource {
            resource_type: None,
        }
    );
}

#[test]
fn resource_scope_only_covers_matching_resource() {
    let assignment = EffectiveRoleAssignment {
        principal_id: None,
        role_id: "role_reader".to_string(),
        scope_type: Some("resource:document".to_string()),
        scope_id: Some("doc_1".to_string()),
        expires_at: None,
    };

    assert!(role_assignment_covers_resource(
        &assignment,
        "document",
        "doc_1",
        None
    ));
    assert!(!role_assignment_covers_resource(
        &assignment,
        "document",
        "doc_2",
        None
    ));
}
