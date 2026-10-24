use proptest::prelude::*;

use crate::{ActionDefinition, ActionPatternExpandError, ResourceType, expand_action_patterns};

fn fixture_resource_types() -> Vec<ResourceType> {
    vec![
        ResourceType {
            id: "document".into(),
            name: "document".into(),
            description: None,
            actions: vec![
                ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                ActionDefinition {
                    name: "write".into(),
                    description: None,
                },
                ActionDefinition {
                    name: "delete".into(),
                    description: None,
                },
            ],
            context_schema: None,
        },
        ResourceType {
            id: "billing_document".into(),
            name: "billing_document".into(),
            description: None,
            actions: vec![
                ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                ActionDefinition {
                    name: "archive".into(),
                    description: None,
                },
            ],
            context_schema: None,
        },
    ]
}

#[test]
fn expands_exact_patterns() {
    let expanded = expand_action_patterns(
        fixture_resource_types().as_slice(),
        "document",
        "read",
        64,
        32,
    )
    .expect("exact pattern should expand");
    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0].resource_type, "document");
    assert_eq!(expanded[0].action_name, "read");
}

#[test]
fn expands_full_wildcard_pattern() {
    let expanded = expand_action_patterns(fixture_resource_types().as_slice(), "*", "*", 64, 32)
        .expect("full wildcard should expand");
    assert_eq!(expanded.len(), 5);
    assert_eq!(expanded[0].resource_type, "billing_document");
    assert_eq!(expanded[0].action_name, "archive");
    assert_eq!(expanded[4].resource_type, "document");
    assert_eq!(expanded[4].action_name, "write");
}

#[test]
fn expands_prefix_suffix_patterns() {
    let expanded = expand_action_patterns(
        fixture_resource_types().as_slice(),
        "*document",
        "re*",
        64,
        32,
    )
    .expect("prefix/suffix wildcard should expand");
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded[0].resource_type, "billing_document");
    assert_eq!(expanded[0].action_name, "read");
    assert_eq!(expanded[1].resource_type, "document");
    assert_eq!(expanded[1].action_name, "read");
}

#[test]
fn rejects_infix_wildcard() {
    let error = expand_action_patterns(
        fixture_resource_types().as_slice(),
        "do*ment",
        "read",
        64,
        32,
    )
    .expect_err("infix wildcard should fail");
    assert!(matches!(error, ActionPatternExpandError::InvalidPattern(_)));
}

#[test]
fn rejects_zero_match_wildcard() {
    let error = expand_action_patterns(
        fixture_resource_types().as_slice(),
        "document",
        "admin*",
        64,
        32,
    )
    .expect_err("zero-match wildcard should fail");
    assert!(matches!(
        error,
        ActionPatternExpandError::NoMatches {
            used_wildcard: true,
            ..
        }
    ));
}

fn catalog_strategy() -> impl Strategy<Value = Vec<ResourceType>> {
    prop::collection::hash_set("[a-z]{1,6}", 1..3).prop_flat_map(|types| {
        let actions = prop::collection::hash_set("[a-z]{1,6}", 1..3);
        (Just(types), actions).prop_map(|(types, actions)| {
            types
                .into_iter()
                .map(|id| ResourceType {
                    name: id.clone(),
                    description: None,
                    actions: actions
                        .iter()
                        .map(|name| ActionDefinition {
                            name: name.clone(),
                            description: None,
                        })
                        .collect(),
                    context_schema: None,
                    id,
                })
                .collect()
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn given_any_patterns_when_expanding_then_no_wildcard_escapes(
        catalog in catalog_strategy(),
        type_pattern in "[a-z*]{1,8}",
        action_pattern in "[a-z*]{1,8}",
    ) {
        // Given arbitrary patterns over a generated catalog.
        // When expansion runs.
        let result = expand_action_patterns(&catalog, &type_pattern, &action_pattern, 64, 32);

        // Then a successful expansion never leaks wildcard syntax into the
        // validated refs, and determinism holds across repeated runs.
        if let Ok(expanded) = &result {
            for reference in expanded {
                prop_assert!(!reference.resource_type.contains('*'));
                prop_assert!(!reference.action_name.contains('*'));
            }
            prop_assert_eq!(
                &expand_action_patterns(&catalog, &type_pattern, &action_pattern, 64, 32)
                    .expect("deterministic expansion"),
                expanded
            );
        }
    }

    #[test]
    fn given_match_all_patterns_when_expanding_then_full_catalog_returns(
        catalog in catalog_strategy(),
    ) {
        // Given match-all patterns over a non-empty catalog.
        let expanded = expand_action_patterns(&catalog, "*", "*", 64, 32)
            .expect("match-all expansion");

        // When every catalog pair is enumerated.
        let expected: usize = catalog.iter().map(|kind| kind.actions.len()).sum();

        // Then expansion returns exactly the catalog membership, sorted and
        // deduplicated by construction.
        prop_assert_eq!(expanded.len(), expected);
    }

    #[test]
    fn given_exact_member_pattern_when_expanding_then_singleton_returns(
        catalog in catalog_strategy(),
    ) {
        // Given an exact pattern naming a catalog member.
        let kind = &catalog[0];
        let action = &kind.actions[0];

        // When expansion runs for that exact pair.
        let expanded =
            expand_action_patterns(&catalog, &kind.id, &action.name, 64, 32)
                .expect("exact expansion");

        // Then exactly that pair returns, with catalog spelling preserved.
        prop_assert_eq!(expanded.len(), 1);
        prop_assert_eq!(&expanded[0].resource_type, &kind.id);
        prop_assert_eq!(&expanded[0].action_name, &action.name);
    }
}
