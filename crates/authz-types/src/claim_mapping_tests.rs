use std::collections::BTreeMap;

use serde_json::json;

use crate::{
    ClaimMappingError, ClaimMappingMatcher, ClaimMappingOutput, ClaimMappingRegistry,
    ClaimMappingSpec, ClaimPath, ClaimTemplate, VerifiedClaimTree,
};

fn exact_spec(source: &str, target: &str) -> ClaimMappingSpec {
    ClaimMappingSpec {
        source: ClaimPath::parse(source).expect("path"),
        target: target.into(),
        output: ClaimMappingOutput::AccessToken,
        matcher: ClaimMappingMatcher::Exact,
        pattern: None,
        key_pattern: None,
        template: ClaimTemplate::Source,
    }
}

#[test]
fn exact_mapping_copies_nested_json_without_loss() {
    let registry =
        ClaimMappingRegistry::compile(vec![exact_spec("$.profile", "application_profile")])
            .expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({
        "profile": {"tier": "enterprise", "nullable": null, "roles": ["a", "a"]}
    }))
    .expect("tree");
    let rendered = registry.render(&tree).expect("render");
    assert_eq!(
        rendered["application_profile"],
        json!({
            "tier": "enterprise", "nullable": null, "roles": ["a", "a"]
        })
    );
}

#[test]
fn regex_mapping_compiles_once_and_renders_typed_nested_template() {
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.email").expect("path"),
        "identity".into(),
        r"^(?P<local>[a-z]+)@(?P<domain>[a-z.]+)$".into(),
        ClaimTemplate::Object {
            fields: BTreeMap::from([
                (
                    "local".into(),
                    ClaimTemplate::Capture {
                        name: "local".into(),
                    },
                ),
                (
                    "domain".into(),
                    ClaimTemplate::Capture {
                        name: "domain".into(),
                    },
                ),
                (
                    "kind".into(),
                    ClaimTemplate::Literal {
                        value: json!("email"),
                    },
                ),
            ]),
        },
    )])
    .expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({"email": "alice@example.test"})).expect("tree");
    assert_eq!(
        registry.render(&tree).expect("render")["identity"],
        json!({
            "local": "alice",
            "domain": "example.test",
            "kind": "email"
        })
    );
}

#[test]
fn mappings_reject_protected_and_duplicate_targets() {
    let protected = ClaimMappingRegistry::compile(vec![exact_spec("$.sub", "sub")])
        .expect_err("protected target");
    assert!(matches!(protected, ClaimMappingError::ProtectedTarget(_)));

    let duplicate =
        ClaimMappingRegistry::compile(vec![exact_spec("$.a", "same"), exact_spec("$.b", "same")])
            .expect_err("duplicate target");
    assert!(matches!(duplicate, ClaimMappingError::DuplicateTarget(_)));
}

#[test]
fn entry_mapping_captures_key_and_value_into_a_bounded_array() {
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entitlements").expect("path"),
        "application_roles".into(),
        r"^app-(?P<application>[a-z]+)$".into(),
        Some(r"^(?P<role>[a-z]+):(?P<level>[0-9]+)$".into()),
        ClaimTemplate::Object {
            fields: BTreeMap::from([
                (
                    "application".into(),
                    ClaimTemplate::Capture {
                        name: "application".into(),
                    },
                ),
                (
                    "role".into(),
                    ClaimTemplate::Capture {
                        name: "role".into(),
                    },
                ),
                (
                    "level".into(),
                    ClaimTemplate::Capture {
                        name: "level".into(),
                    },
                ),
            ]),
        },
    )])
    .expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({
        "entitlements": {
            "app-billing": "admin:2",
            "app-console": "viewer:1",
            "other": "ignored:9"
        }
    }))
    .expect("tree");
    assert_eq!(
        registry.render(&tree).expect("render")["application_roles"],
        json!([
            {"application": "billing", "role": "admin", "level": "2"},
            {"application": "console", "role": "viewer", "level": "1"}
        ])
    );
}

#[test]
fn entry_mapping_rejects_duplicate_key_and_value_capture_names() {
    let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entitlements").expect("path"),
        "roles".into(),
        r"^app-(?P<name>[a-z]+)$".into(),
        Some(r"^(?P<name>[a-z]+)$".into()),
        ClaimTemplate::Capture {
            name: "name".into(),
        },
    )])
    .expect_err("duplicate capture");
    assert!(matches!(error, ClaimMappingError::DuplicateCapture(name) if name == "name"));
}

#[test]
fn claim_paths_are_utf8_safe_and_reject_control_characters() {
    let unicode_path = ClaimPath::parse("$.café[0].😀").expect("unicode path");
    let claims = VerifiedClaimTree::try_new(json!({
        "café": [{"😀": "ok"}]
    }))
    .expect("tree");
    let mut mapping = exact_spec("$.value", "value");
    mapping.source = unicode_path;
    let registry = ClaimMappingRegistry::compile(vec![mapping]).expect("unicode registry");
    assert_eq!(
        registry.render(&claims).expect("unicode render")["value"],
        json!("ok")
    );
    assert!(ClaimPath::parse("$.line\u{2003}break").is_err());
    assert!(ClaimPath::parse("$.zero\u{200b}width").is_err());
    assert!(ClaimPath::parse("$.direction\u{202e}override").is_err());
    assert!(ClaimPath::parse("$.nul\0byte").is_err());
}

#[test]
fn malformed_json_and_invalid_shapes_fail_closed_without_panicking() {
    let malformed = serde_json::from_slice::<ClaimMappingSpec>(
        br#"{"source":"$.email","target":"identity","template":{"type":"source"}"#,
    );
    assert!(malformed.is_err());

    let mut invalid_utf8 =
        br#"{"source":"$.email","target":"identity","template":{"type":"source"},"pattern":""}"#
            .to_vec();
    invalid_utf8.push(0xff);
    let invalid_utf8 = serde_json::from_slice::<ClaimMappingSpec>(&invalid_utf8);
    assert!(invalid_utf8.is_err());

    let duplicate_field = serde_json::from_str::<ClaimMappingSpec>(
        r#"{"source":"$.email","target":"first","target":"second","template":{"type":"source"}}"#,
    );
    assert!(duplicate_field.is_err());

    let wrong_source = serde_json::from_str::<ClaimMappingSpec>(
        r#"{"source":42,"target":"identity","template":{"type":"source"}}"#,
    );
    assert!(wrong_source.is_err());
}

#[test]
fn regex_subset_rejects_complexity_and_engine_escape_hatches() {
    for pattern in [
        r"(?=a)",
        r"(?!a)",
        r"(?<=a)",
        r"(?<!a)",
        r"(?i:a)",
        r"^(a+)+$",
        r"^(a*)*$",
        r"^(?:a){0,129}$",
        r"^(?:a){129,129}$",
        r"^(?P<a>a)\1$",
        r"^(?P<a>a)\k<a>$",
        r"^(?:a){2,}$",
        r"^(?:a){2,1}$",
        r"^(?:a){2}{3}$",
        r"^(?:a){2,3,4}$",
        r"^(?:(?:a+))*$",
        r"^(?:a)(?P<>)$",
        r"^(?:a)(?P<na-me>)$",
        r"^(?:a)(?P<name>$",
        r"^(?:a)[\p{L}]$",
        r"^(?:a)[\b]$",
        r"^(?:a)[\x00]$",
        r"^(?:a)\u{202e}$",
    ] {
        let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
            ClaimPath::parse("$.value").expect("path"),
            format!("target_{pattern}"),
            pattern.into(),
            ClaimTemplate::Source,
        )])
        .expect_err("unsafe regex should be rejected");
        assert!(
            matches!(error, ClaimMappingError::InvalidPattern),
            "{pattern}"
        );
    }

    let bidi_pattern = format!("^(?:a){}$", '\u{202e}');
    let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "bidi".into(),
        bidi_pattern,
        ClaimTemplate::Source,
    )])
    .expect_err("format characters should be rejected");
    assert!(matches!(error, ClaimMappingError::InvalidPattern));

    let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entries").expect("path"),
        "entries".into(),
        r"(?=unsafe)".into(),
        None,
        ClaimTemplate::Source,
    )])
    .expect_err("key regex lookahead should be rejected");
    assert!(matches!(error, ClaimMappingError::InvalidPattern));
}

#[test]
fn regex_subset_keeps_named_and_non_capturing_groups_usable() {
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "normalized".into(),
        r"^(?:prefix-)?(?P<value>[a-z]+)$".into(),
        ClaimTemplate::Capture {
            name: "value".into(),
        },
    )])
    .expect("supported regex");
    let claims = VerifiedClaimTree::try_new(json!({"value": "prefix-alice"})).expect("tree");
    assert_eq!(
        registry.render(&claims).expect("render")["normalized"],
        json!("alice")
    );
}

#[test]
fn regex_subset_enforces_depth_and_quantifier_count_bounds() {
    let nested_groups = format!("{}a{}", "(?:".repeat(33), ")".repeat(33));
    let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "too_deep".into(),
        nested_groups,
        ClaimTemplate::Source,
    )])
    .expect_err("deep groups should be rejected");
    assert!(matches!(error, ClaimMappingError::InvalidPattern));

    let too_many_quantifiers = format!("^{}$", "a?".repeat(65));
    let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "too_many_quantifiers".into(),
        too_many_quantifiers,
        ClaimTemplate::Source,
    )])
    .expect_err("too many quantifiers should be rejected");
    assert!(matches!(error, ClaimMappingError::InvalidPattern));

    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "bounded".into(),
        r"^(?:a){0,128}$".into(),
        ClaimTemplate::Source,
    )])
    .expect("the inclusive repetition bound should remain usable");
    let claims = VerifiedClaimTree::try_new(json!({"value": "aaaa"})).expect("tree");
    assert_eq!(
        registry.render(&claims).expect("render")["bounded"],
        json!("aaaa")
    );
}

#[test]
fn output_names_and_template_keys_reject_control_characters() {
    let mut spec = exact_spec("$.value", "safe");
    spec.target = "unsafe\u{000b}target".into();
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![spec]),
        Err(ClaimMappingError::InvalidTarget)
    ));

    let mut template = BTreeMap::new();
    template.insert("unsafe\u{000b}key".into(), ClaimTemplate::Source);
    let mut spec = exact_spec("$.value", "safe");
    spec.template = ClaimTemplate::Object { fields: template };
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![spec]),
        Err(ClaimMappingError::InvalidCapture)
    ));
}
