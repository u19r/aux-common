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
