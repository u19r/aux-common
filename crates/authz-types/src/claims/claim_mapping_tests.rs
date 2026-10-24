use std::collections::BTreeMap;

use serde_json::json;

use crate::{
    ClaimMappingError, ClaimMappingMatcher, ClaimMappingOutput, ClaimMappingRegistry,
    ClaimMappingSpec, ClaimPath, ClaimTemplate, MAX_CLAIM_MAPPING_PATH_BYTES,
    MAX_CLAIM_MAPPING_PATTERN_BYTES, MAX_CLAIM_MAPPINGS, VerifiedClaimTree,
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
    for target in ["sub", "access_profile_session_reference"] {
        let protected = ClaimMappingRegistry::compile(vec![exact_spec("$.sub", target)])
            .expect_err("protected target");
        assert_eq!(protected, ClaimMappingError::ProtectedTarget(target.into()));
    }

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

#[test]
fn given_bounded_json_paths_when_parsing_malformed_inputs_then_rejects_without_panicking() {
    // Given a root path and malformed variants of the supported JSONPath
    // subset.
    assert!(ClaimPath::parse("$").is_ok());
    let oversized = format!("$.{}", "a".repeat(MAX_CLAIM_MAPPING_PATH_BYTES));
    for path in [
        "",
        "profile",
        "$.",
        "$..name",
        "$[x]",
        "$[0",
        "$profile",
        "$.\u{000b}",
    ]
    .into_iter()
    .chain([oversized.as_str()])
    {
        // When an input is not exactly a bounded path, parsing fails closed.
        assert!(matches!(
            ClaimPath::parse(path),
            Err(ClaimMappingError::InvalidPath)
        ));
    }
    // Then malformed paths never produce a partial path value.
}

#[test]
fn given_serialized_claim_paths_when_round_tripping_and_compiling_then_bounds_remain_lossless() {
    // Given a valid path represented by its persisted serde form.
    let path = ClaimPath::parse("$.profile[1].name").expect("path");
    let encoded = serde_json::to_value(&path).expect("serialize path");
    assert_eq!(
        encoded,
        json!([{"key": "profile"}, {"index": 1}, {"key": "name"}])
    );
    let decoded: ClaimPath = serde_json::from_value(encoded).expect("deserialize path");
    assert_eq!(decoded, path);

    // When deserialization bypasses the parser, registry validation still
    // rejects unsafe data.
    let mut control_spec = exact_spec("$.unused", "control");
    control_spec.source =
        serde_json::from_value(json!([{"key": "bad\u{000b}key"}])).expect("serialized path");
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![control_spec]),
        Err(ClaimMappingError::InvalidPath)
    ));

    let mut oversized_spec = exact_spec("$.unused", "oversized");
    oversized_spec.source = serde_json::from_value(json!([{
        "key": "a".repeat(MAX_CLAIM_MAPPING_PATH_BYTES)
    }]))
    .expect("serialized path");
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![oversized_spec]),
        Err(ClaimMappingError::InvalidPath)
    ));
    // Then both parser-bypassing inputs remain rejected at the registry
    // boundary.
}

#[test]
fn given_array_and_object_templates_when_rendering_then_nested_values_are_lossless() {
    // Given a template containing every renderable composite shape.
    let template = ClaimTemplate::Array {
        items: vec![
            ClaimTemplate::Source,
            ClaimTemplate::Literal { value: json!(null) },
            ClaimTemplate::Object {
                fields: BTreeMap::from([("copied".into(), ClaimTemplate::Source)]),
            },
        ],
    };
    let mut spec = exact_spec("$.profile", "profiles");
    spec.template = template;
    let serialized = serde_json::to_value(&spec).expect("serialize spec");
    let restored: ClaimMappingSpec = serde_json::from_value(serialized).expect("spec round trip");
    assert_eq!(restored, spec);

    // When the registry renders it, every nested value and duplicate array
    // entry is preserved.
    let registry = ClaimMappingRegistry::compile(vec![restored]).expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({
        "profile": {"tier": "enterprise", "roles": ["reader", "reader"]}
    }))
    .expect("tree");
    assert_eq!(
        registry.render(&tree).expect("render")["profiles"],
        json!([
            {"tier": "enterprise", "roles": ["reader", "reader"]},
            null,
            {"copied": {"tier": "enterprise", "roles": ["reader", "reader"]}}
        ])
    );
    // Then serde reconstruction and rendering agree on the same typed contract.
}

#[test]
fn given_invalid_template_values_when_compiling_then_bounds_and_capture_names_fail_closed() {
    // Given a template whose node count exceeds the persisted configuration
    // bound.
    let oversized = ClaimTemplate::Array {
        items: vec![ClaimTemplate::Source; 128],
    };
    let mut spec = exact_spec("$.value", "oversized");
    spec.template = oversized;
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![spec]),
        Err(ClaimMappingError::TemplateTooLarge)
    ));

    // When a capture name is empty or a literal exceeds canonical claim bounds,
    // compilation fails.
    let mut invalid_capture = exact_spec("$.value", "capture");
    invalid_capture.template = ClaimTemplate::Capture {
        name: String::new(),
    };
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![invalid_capture]),
        Err(ClaimMappingError::InvalidCapture)
    ));

    let mut oversized_literal = exact_spec("$.value", "literal");
    oversized_literal.template = ClaimTemplate::Literal {
        value: json!("x".repeat(MAX_CLAIM_MAPPING_PATH_BYTES + 1)),
    };
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![oversized_literal]),
        Err(ClaimMappingError::Bounds(_))
    ));
    // Then no invalid literal or capture can reach request-time rendering.
}

#[test]
fn given_empty_and_overfull_registries_when_inspecting_then_state_and_bounds_are_explicit() {
    // Given no mappings and then one valid mapping.
    let empty = ClaimMappingRegistry::default();
    assert!(empty.is_empty());
    let populated =
        ClaimMappingRegistry::compile(vec![exact_spec("$.value", "value")]).expect("registry");
    assert!(!populated.is_empty());

    // When the configured mapping count exceeds the startup bound, compilation
    // rejects it.
    let specs = (0..=MAX_CLAIM_MAPPINGS)
        .map(|index| exact_spec("$.value", &format!("value_{index}")))
        .collect();
    assert!(matches!(
        ClaimMappingRegistry::compile(specs),
        Err(ClaimMappingError::TemplateTooLarge)
    ));
    // Then the empty and overfull states are both explicit and deterministic.
}

#[test]
fn given_mapping_contract_mismatches_when_compiling_then_matcher_requirements_are_enforced() {
    // Given an exact matcher carrying a regex or a regex matcher without one.
    let mut exact_with_pattern = exact_spec("$.value", "exact");
    exact_with_pattern.pattern = Some("value".into());
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![exact_with_pattern]),
        Err(ClaimMappingError::InvalidCapture)
    ));

    let mut regex_without_pattern = exact_spec("$.value", "regex");
    regex_without_pattern.matcher = ClaimMappingMatcher::Regex;
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![regex_without_pattern]),
        Err(ClaimMappingError::InvalidPattern)
    ));

    // When a template names a capture absent from both regexes, compilation
    // rejects the mapping.
    let missing_capture = ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "missing_capture".into(),
        r"^(?P<present>[a-z]+)$".into(),
        ClaimTemplate::Capture {
            name: "missing".into(),
        },
    );
    assert!(matches!(
        ClaimMappingRegistry::compile(vec![missing_capture]),
        Err(ClaimMappingError::InvalidCapture)
    ));
    // Then matcher/template mismatches cannot produce a partially compiled
    // registry.
}

#[test]
fn given_same_target_in_distinct_outputs_when_rendering_then_output_ownership_isolated() {
    // Given two output artifacts that intentionally use the same top-level
    // claim name.
    let access = exact_spec("$.value", "shared");
    let mut id_token = exact_spec("$.other", "shared");
    id_token.output = ClaimMappingOutput::IdToken;
    let registry = ClaimMappingRegistry::compile(vec![access.clone(), id_token]).expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({"value": "access", "other": "id"})).expect("tree");

    // When each output is rendered, it receives only its own mapping.
    assert_eq!(
        registry.render(&tree).expect("access render")["shared"],
        "access"
    );
    assert_eq!(
        registry
            .render_for(ClaimMappingOutput::IdToken, &tree)
            .expect("id render")["shared"],
        "id"
    );
    assert!(
        registry
            .render_for(ClaimMappingOutput::SamlAssertion, &tree)
            .expect("saml render")
            .is_empty()
    );
    // Then duplicate target names remain isolated by output artifact.
}

#[test]
fn given_exact_entry_mapping_when_rendering_then_sorted_object_values_and_key_captures_survive() {
    // Given an entry selector without a value regex, including object-valued
    // entries.
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entitlements").expect("path"),
        "roles".into(),
        r"^app-(?P<application>[a-z]+)$".into(),
        None,
        ClaimTemplate::Object {
            fields: BTreeMap::from([
                (
                    "application".into(),
                    ClaimTemplate::Capture {
                        name: "application".into(),
                    },
                ),
                ("value".into(), ClaimTemplate::Source),
            ]),
        },
    )])
    .expect("registry");
    let tree = VerifiedClaimTree::try_new(json!({
        "entitlements": {
            "app-zeta": {"level": 2},
            "app-alpha": {"level": 1}
        }
    }))
    .expect("tree");

    // When rendered, matching keys are sorted independently of source JSON
    // insertion order.
    assert_eq!(
        registry.render(&tree).expect("render")["roles"],
        json!([
            {"application": "alpha", "value": {"level": 1}},
            {"application": "zeta", "value": {"level": 2}}
        ])
    );
    // Then each selected entry is represented once with its original JSON
    // value.
}

#[test]
fn given_entry_mapping_shape_or_selector_failures_when_rendering_then_errors_are_specific() {
    // Given a key selector whose source is not an object and one with no
    // matching entries.
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entitlements").expect("path"),
        "roles".into(),
        r"^app-(?P<application>[a-z]+)$".into(),
        None,
        ClaimTemplate::Source,
    )])
    .expect("registry");

    // When the source shape is wrong, rendering fails closed without coercion.
    let scalar =
        VerifiedClaimTree::try_new(json!({"entitlements": "not-an-object"})).expect("tree");
    assert!(matches!(
        registry.render(&scalar),
        Err(ClaimMappingError::SourceNotObject)
    ));

    // When no key matches, rendering reports the absence rather than returning
    // an empty array.
    let unmatched =
        VerifiedClaimTree::try_new(json!({"entitlements": {"other": "ignored"}})).expect("tree");
    assert!(matches!(
        registry.render(&unmatched),
        Err(ClaimMappingError::Render(message)) if message == "key regex did not match an object entry"
    ));
    // Then shape and selector failures are observable as typed errors.
}

#[test]
fn given_entry_value_regex_failures_when_rendering_then_type_and_match_errors_are_distinct() {
    // Given a value matcher applied to a selected object entry.
    let spec = ClaimMappingSpec::entry_regex(
        ClaimPath::parse("$.entitlements").expect("path"),
        "roles".into(),
        r"^app-(?P<application>[a-z]+)$".into(),
        Some(r"^(?P<role>[a-z]+)$".into()),
        ClaimTemplate::Capture {
            name: "role".into(),
        },
    );
    let registry = ClaimMappingRegistry::compile(vec![spec]).expect("registry");

    // When a matching entry is not a string, rendering refuses an implicit
    // conversion.
    let non_string = VerifiedClaimTree::try_new(json!({
        "entitlements": {"app-console": {"role": "viewer"}}
    }))
    .expect("tree");
    assert!(matches!(
        registry.render(&non_string),
        Err(ClaimMappingError::SourceNotString)
    ));

    // When a string entry does not satisfy the matcher, rendering reports the
    // failed contract.
    let mismatch = VerifiedClaimTree::try_new(json!({
        "entitlements": {"app-console": "viewer:read"}
    }))
    .expect("tree");
    assert!(matches!(
        registry.render(&mismatch),
        Err(ClaimMappingError::Render(message))
            if message == "regex did not match an object entry value"
    ));
    // Then entry value errors remain distinct and fail closed.
}

#[test]
fn given_regex_mapping_type_or_match_failures_when_rendering_then_it_fails_closed() {
    // Given a regex mapping over a string source.
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.email").expect("path"),
        "identity".into(),
        r"^(?P<local>[a-z]+)@example\.test$".into(),
        ClaimTemplate::Capture {
            name: "local".into(),
        },
    )])
    .expect("registry");

    // When the source is not a string, rendering does not stringify it.
    let non_string =
        VerifiedClaimTree::try_new(json!({"email": {"local": "alice"}})).expect("tree");
    assert!(matches!(
        registry.render(&non_string),
        Err(ClaimMappingError::SourceNotString)
    ));

    // When the source string does not match, rendering reports the failed regex
    // contract.
    let mismatch = VerifiedClaimTree::try_new(json!({"email": "alice@other.test"})).expect("tree");
    assert!(matches!(
        registry.render(&mismatch),
        Err(ClaimMappingError::Render(message)) if message == "regex did not match"
    ));

    let missing = VerifiedClaimTree::try_new(json!({"other": "alice@example.test"})).expect("tree");
    assert!(matches!(
        registry.render(&missing),
        Err(ClaimMappingError::SourceNotFound)
    ));
    // Then regex mappings never coerce, invent, or silently omit their source.
}

#[test]
fn given_regex_subset_boundary_inputs_when_compiling_then_unsafe_forms_are_rejected() {
    // Given malformed, oversized, and unsupported forms at each parser
    // boundary.
    let patterns = [
        String::new(),
        "a".repeat(MAX_CLAIM_MAPPING_PATTERN_BYTES + 1),
        format!("[{}", '\\'),
        r"[\x]".into(),
        r"(?P<name".into(),
        "^?".into(),
        "^{1}".into(),
        "a{".into(),
        "}".into(),
        "[a".into(),
        "[z-a]".into(),
        "a*".repeat(65),
        "a{1}".repeat(65),
    ];
    for pattern in patterns {
        // When a persisted pattern violates the restricted regex language,
        // compilation rejects it.
        let error = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
            ClaimPath::parse("$.value").expect("path"),
            format!("target_{}", pattern.len()),
            pattern,
            ClaimTemplate::Source,
        )])
        .expect_err("unsafe regex should be rejected");
        assert!(matches!(error, ClaimMappingError::InvalidPattern));
    }
    // Then every boundary form is rejected before the regex engine is invoked.
}

#[test]
fn given_supported_regex_forms_when_compiling_then_matching_is_deterministic() {
    // Given alternation, character classes, anchors, and simple escaped
    // classes.
    let registry = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "normalized".into(),
        r"\A(?:a?|b+|c{1})[a-z]*\z".into(),
        ClaimTemplate::Source,
    )])
    .expect("supported regex");
    let tree = VerifiedClaimTree::try_new(json!({"value": "alice"})).expect("tree");

    // When a supported form matches, its source value is returned exactly once.
    assert_eq!(
        registry.render(&tree).expect("render")["normalized"],
        "alice"
    );

    // When a bounded repetition is outside a group, it remains valid and
    // bounded.
    let bounded = ClaimMappingRegistry::compile(vec![ClaimMappingSpec::regex(
        ClaimPath::parse("$.value").expect("path"),
        "bounded".into(),
        r"a{1}".into(),
        ClaimTemplate::Source,
    )])
    .expect("bounded regex");
    let tree = VerifiedClaimTree::try_new(json!({"value": "a"})).expect("tree");
    assert_eq!(bounded.render(&tree).expect("render")["bounded"], "a");
    // Then supported alternation, escapes, and bounded repetition retain exact
    // values.
}
