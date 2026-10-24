use proptest::prelude::*;

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

fn same_scope_kind(left: ScopeKind<'_>, right: ScopeKind<'_>) -> bool {
    match (left, right) {
        (ScopeKind::Tenant, ScopeKind::Tenant)
        | (ScopeKind::Org, ScopeKind::Org)
        | (ScopeKind::Group, ScopeKind::Group)
        | (ScopeKind::Other, ScopeKind::Other) => true,
        (
            ScopeKind::Resource {
                resource_type: left,
            },
            ScopeKind::Resource {
                resource_type: right,
            },
        ) => match (left, right) {
            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
            (None, None) => true,
            _ => false,
        },
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn given_any_scope_string_when_classifying_then_case_and_padding_never_change_kind(
        scope in "[\x00-\x7F]{0,24}",
    ) {
        // Given an arbitrary scope string.
        // When ASCII case and surrounding padding vary.
        let upper = scope.to_ascii_uppercase();
        let padded = format!(" {scope} ");

        // Then classification is total and insensitive to caller casing and
        // padding, so two spellings of one scope cannot take different
        // authorization paths. Resource suffixes keep their spelling but
        // compare case-insensitively downstream.
        prop_assert!(same_scope_kind(
            classify_scope(&scope),
            classify_scope(&upper)
        ));
        prop_assert_eq!(classify_scope(&scope), classify_scope(&padded));
    }

    #[test]
    fn given_resource_prefixed_scope_when_classifying_then_type_is_exact_or_absent(
        suffix in "[A-Za-z0-9_.:-]{0,16}",
    ) {
        // Given a resource-prefixed scope with an arbitrary suffix.
        let scope = format!("resource:{suffix}");

        // When classification runs.
        // Then the suffix is taken verbatim when non-empty and absent when
        // empty, never confused with the bare resource scope.
        match classify_scope(&scope) {
            ScopeKind::Resource { resource_type: Some(kind) } => {
                prop_assert_eq!(kind, suffix.as_str());
            }
            ScopeKind::Resource { resource_type: None } => {
                prop_assert!(suffix.is_empty());
            }
            ScopeKind::Tenant | ScopeKind::Org | ScopeKind::Group | ScopeKind::Other => {
                prop_assert!(false, "resource-prefixed scope escaped classification");
            }
        }
    }
}
