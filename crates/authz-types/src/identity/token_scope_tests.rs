use std::collections::HashMap;

use crate::{FineGrainedScopes, ResourceSelection, TokenScopeConfig, TokenScopeType};

#[test]
fn token_scope_deserialization_rejects_ambiguous_restrictions() {
    for payload in [
        serde_json::json!({"scope_strings": ["document:read"]}),
        serde_json::json!({
            "scope_type": "full_access",
            "scope_strings": ["document:read"]
        }),
    ] {
        let error = serde_json::from_value::<TokenScopeConfig>(payload)
            .expect_err("restricted token scope must have one unambiguous discriminator");
        assert!(
            error.to_string().contains("scope_type") || error.to_string().contains("full_access")
        );
    }
}

#[test]
fn token_scope_deserialization_preserves_explicit_full_access_default() {
    let decoded = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({}))
        .expect("an empty scope object retains the documented full-access default");
    assert_eq!(decoded.scope_type(), crate::TokenScopeType::FullAccess);
}

#[test]
fn token_scope_deserialization_bounds_nested_collections() {
    let too_many_scope_strings = serde_json::json!({
        "scope_type": "scope_strings",
        "scope_strings": (0..=200).map(|index| format!("doc:{index}")).collect::<Vec<_>>()
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_scope_strings)
            .expect_err("scope strings must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );

    let too_many_selected_resources = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_selection": "selected",
            "selected_resources": (0..=1000).map(|index| format!("doc_{index}")).collect::<Vec<_>>()
        }
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_selected_resources)
            .expect_err("selected resources must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );

    let too_many_permission_values = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_permissions": {
                "document": (0..=500).map(|index| format!("doc:{index}")).collect::<Vec<_>>()
            }
        }
    });
    assert!(
        serde_json::from_value::<TokenScopeConfig>(too_many_permission_values)
            .expect_err("permission values must be bounded")
            .to_string()
            .contains("sequence exceeds maximum")
    );
}

fn token_scope_error(payload: serde_json::Value) -> String {
    serde_json::from_value::<TokenScopeConfig>(payload)
        .expect_err("token scope payload should be rejected")
        .to_string()
}

fn token_scope_json_error(payload: &str) -> String {
    serde_json::from_str::<TokenScopeConfig>(payload)
        .expect_err("raw token scope payload should be rejected")
        .to_string()
}

#[test]
fn given_default_scope_when_constructing_full_access_then_token_has_no_restriction_fields() {
    // Given no explicit token scope configuration.
    // When the documented full-access constructor is used.
    let scope = TokenScopeConfig::full_access();

    // Then the token inherits the owner's permissions without a derived
    // ceiling.
    assert_eq!(scope.scope_type(), TokenScopeType::FullAccess);
    assert!(scope.scope_strings().is_empty());
    assert!(scope.fine_grained_scopes().is_none());
    assert!(scope.org_id().is_none());
    assert!(scope.resolved_permissions().is_none());
}

#[test]
fn given_coarse_scopes_when_attaching_org_and_resolved_ceiling_then_builder_preserves_fields() {
    // Given a requested coarse-grained permission and its immutable resolution.
    let requested = vec!["document:read".to_string()];
    let resolved = vec!["document:read".to_string()];

    // When the optional token bindings are attached through the builders.
    let scope = TokenScopeConfig::with_scopes(requested.clone())
        .expect("valid coarse scope")
        .with_org("org_123".to_string())
        .expect("valid org binding")
        .with_resolved_permissions(resolved.clone());
    let scope = scope.expect("valid resolved ceiling");

    // Then both the requested scope and the persisted ceiling remain
    // observable.
    assert_eq!(scope.scope_type(), TokenScopeType::ScopeStrings);
    assert_eq!(scope.scope_strings(), requested.as_slice());
    assert_eq!(scope.org_id(), Some("org_123"));
    assert_eq!(scope.resolved_permissions(), Some(resolved.as_slice()));
}

#[test]
fn given_scoped_token_when_attaching_empty_resolved_ceiling_then_builder_rejects_missing_value() {
    // Given a coarse-grained token with a requested scope.
    let scope = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope");

    // When a caller attempts to attach an empty immutable permission ceiling.
    let result = scope.with_resolved_permissions(Vec::new());

    // Then the persisted ceiling must contain at least one resolved permission.
    assert!(matches!(
        result,
        Err(error) if error.to_string().contains(
            "resolved_permissions must contain at least one permission"
        )
    ));
}

#[test]
fn given_scoped_token_when_attaching_duplicate_resolved_permissions_then_builder_rejects_them() {
    // Given a coarse-grained token with a requested scope.
    let scope = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope");

    // When a caller attempts to attach an ambiguous permission ceiling.
    let result = scope.with_resolved_permissions(vec![
        "document:read".to_string(),
        "document:read".to_string(),
    ]);

    // Then duplicate permission ids cannot be persisted as a ceiling.
    assert!(matches!(
        result,
        Err(error) if error.to_string().contains(
            "resolved_permissions must not contain duplicates"
        )
    ));
}

#[test]
fn given_fine_grained_payload_when_constructing_token_scope_then_discriminator_matches_payload() {
    // Given a selected-resource fine-grained allow-list.
    let fine_grained = FineGrainedScopes {
        resource_selection: ResourceSelection::Selected,
        selected_resources: vec!["document:doc_1".to_string()],
        resource_permissions: HashMap::from([(
            "document".to_string(),
            vec!["document:read".to_string()],
        )]),
        org_permissions: HashMap::new(),
    };

    // When the fine-grained constructor is used.
    let scope = TokenScopeConfig::fine_grained(fine_grained).expect("valid fine-grained scope");

    // Then no coarse scope or derived ceiling can accompany the fine-grained
    // payload.
    assert_eq!(scope.scope_type(), TokenScopeType::FineGrained);
    assert!(scope.scope_strings().is_empty());
    assert!(scope.resolved_permissions().is_none());
    assert_eq!(
        scope
            .fine_grained_scopes()
            .expect("constructor stores fine-grained payload")
            .selected_resources,
        vec!["document:doc_1".to_string()]
    );
}

#[test]
fn given_scoped_configuration_when_serializing_and_deserializing_then_wire_contract_round_trips() {
    // Given a bounded scope configuration with an organization binding and
    // ceiling.
    let scope = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope")
        .with_org("org_123".to_string())
        .expect("valid org binding")
        .with_resolved_permissions(vec!["document:read".to_string()]);
    let scope = scope.expect("valid resolved ceiling");

    // When the public wire representation is serialized and decoded again.
    let encoded = serde_json::to_value(&scope).expect("scope serialization should succeed");
    let decoded: TokenScopeConfig =
        serde_json::from_value(encoded.clone()).expect("serialized scope should decode");

    // Then discriminator, requested scope, binding, and immutable ceiling are
    // preserved.
    assert_eq!(encoded["scope_type"], "scope_strings");
    assert_eq!(decoded.scope_type(), TokenScopeType::ScopeStrings);
    assert_eq!(
        decoded.scope_strings(),
        ["document:read".to_string()].as_slice()
    );
    assert_eq!(decoded.org_id(), Some("org_123"));
    assert_eq!(
        decoded.resolved_permissions(),
        Some(["document:read".to_string()].as_slice())
    );
}

#[test]
fn given_full_access_when_attaching_resolved_permissions_then_constructor_rejects_ceiling() {
    // Given an unrestricted token scope.
    // When a caller attempts to attach a persisted restriction ceiling.
    let result = TokenScopeConfig::full_access()
        .with_resolved_permissions(vec!["document:read".to_string()]);

    // Then FullAccess cannot carry a ceiling that its evaluator would ignore.
    assert!(result.is_err());
}

#[test]
fn given_valid_scoped_token_when_reading_canonical_policy_then_configuration_is_available() {
    // Given a valid scoped token created by the canonical builder.
    let scope = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope")
        .with_resolved_permissions(vec!["document:read".to_string()])
        .expect("valid resolved ceiling");

    // Then the evaluator-facing typed policy is available without another
    // check.
    assert_eq!(scope.scope_type(), TokenScopeType::ScopeStrings);
}

#[test]
fn given_scope_strings_with_fine_grained_fields_when_constructing_then_rejected() {
    // Given a coarse token input that names two mutually exclusive models.
    let result = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({
        "scope_type": "scope_strings",
        "scope_strings": ["document:read"],
        "fine_grained": {}
    }));

    // Then a scope-string token cannot carry fine-grained restrictions.
    assert!(result.is_err());
}

#[test]
fn given_fine_grained_scope_with_coarse_fields_when_constructing_then_rejected() {
    // Given fine-grained token inputs paired with each coarse field family.
    let with_scope_strings = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({
        "scope_type": "fine_grained",
        "scope_strings": ["document:read"],
        "fine_grained": {}
    }));
    let with_resolved_permissions = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({
        "scope_type": "fine_grained",
        "resolved_permissions": ["document:read"],
        "fine_grained": {}
    }));

    for result in [with_scope_strings, with_resolved_permissions] {
        // Then fine-grained tokens cannot carry coarse restrictions.
        assert!(result.is_err());
    }
}

#[test]
fn given_fine_grained_discriminator_without_payload_when_decoding_then_rejected() {
    // Given a token discriminator without its required payload.
    let result = serde_json::from_value::<TokenScopeConfig>(serde_json::json!({
        "scope_type": "fine_grained"
    }));

    // Then the fine-grained payload cannot be omitted at evaluation time.
    assert!(result.is_err());
}

#[test]
fn given_all_resource_selection_with_selected_resources_when_constructing_then_rejected() {
    // Given an all-resources fine-grained token with a contradictory resource
    // list.
    let result = TokenScopeConfig::fine_grained(FineGrainedScopes {
        resource_selection: ResourceSelection::All,
        selected_resources: vec!["document:doc_1".to_string()],
        ..FineGrainedScopes::default()
    });

    // Then an all-resources token cannot carry a selected-resource allow-list.
    assert!(matches!(
        result,
        Err(error) if error.to_string().contains(
            "resource_selection=all cannot include selected_resources"
        )
    ));
}

#[test]
fn given_valid_fine_grained_scope_when_reading_canonical_policy_then_selection_is_accepted() {
    // Given an all-resources fine-grained token with no contradictory selection
    // list.
    let result = TokenScopeConfig::fine_grained(FineGrainedScopes::default());

    // Then the valid selection mode passes unchanged.
    assert!(result.is_ok());
}

#[test]
fn given_scoped_token_with_empty_or_duplicate_ceiling_when_constructing_then_rejected() {
    // Given malformed ceilings introduced through the compatibility builder.
    let empty = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope")
        .with_resolved_permissions(Vec::new());
    let duplicate = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope")
        .with_resolved_permissions(vec![
            "document:read".to_string(),
            "document:read".to_string(),
        ]);

    // Then empty and ambiguous ceilings fail closed before authorization.
    assert!(matches!(
        empty,
        Err(error) if error.to_string().contains(
            "resolved_permissions must contain at least one permission"
        )
    ));
    assert!(matches!(
        duplicate,
        Err(error) if error.to_string().contains(
            "resolved_permissions must not contain duplicates"
        )
    ));
}

#[test]
fn given_unique_resolved_ceiling_when_reading_canonical_policy_then_scope_is_accepted() {
    // Given a scoped token with a non-empty, unique immutable ceiling.
    let result = TokenScopeConfig::with_scopes(vec!["document:read".to_string()])
        .expect("valid coarse scope")
        .with_resolved_permissions(vec!["document:read".to_string()]);

    // Then the valid ceiling remains available to authorization.
    assert!(result.is_ok());
}

#[test]
fn given_empty_scope_strings_with_a_ceiling_then_canonical_policy_rejects_it() {
    // Given the compatibility constructor used with an empty requested scope
    // list.
    let result = TokenScopeConfig::with_scopes(Vec::new())
        .expect("empty scope list is valid without a ceiling")
        .with_resolved_permissions(vec!["document:alpha".to_string()]);

    // Then the detached ceiling is rejected before any evaluator can use it.
    assert!(result.is_err());
}

#[test]
fn given_constructed_selected_scope_without_resources_then_canonical_policy_rejects_it() {
    // Given a fine-grained value that bypasses wire deserialization.
    let result = TokenScopeConfig::fine_grained(FineGrainedScopes {
        resource_selection: ResourceSelection::Selected,
        ..FineGrainedScopes::default()
    });

    // Then public construction cannot smuggle an empty selected allow-list into
    // evaluation.
    assert!(result.is_err());
}

#[test]
fn given_explicit_full_access_with_null_optionals_when_decoding_then_defaults_are_preserved() {
    // Given an explicit unrestricted discriminator and JSON null optionals.
    let payload = serde_json::json!({
        "scope_type": "full_access",
        "org_id": null,
        "resolved_permissions": null
    });

    // When the public token scope boundary decodes the payload.
    let decoded = serde_json::from_value::<TokenScopeConfig>(payload)
        .expect("explicit full-access payload should decode");

    // Then null optional fields retain absence semantics and no ceiling is
    // created.
    assert_eq!(decoded.scope_type(), TokenScopeType::FullAccess);
    assert!(decoded.org_id().is_none());
    assert!(decoded.resolved_permissions().is_none());
}

#[test]
fn given_fine_grained_wire_payload_when_decoding_then_resource_and_org_maps_are_preserved() {
    // Given both resource-level and organization-level fine-grained ceilings.
    let payload = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_selection": "selected",
            "selected_resources": ["document:doc_1", "document:doc_2"],
            "resource_permissions": {
                "document": ["document:read", "document:write"]
            },
            "org_permissions": {"org_123": ["organization:manage"]}
        }
    });

    // When the payload crosses the deserialization boundary.
    let decoded = serde_json::from_value::<TokenScopeConfig>(payload)
        .expect("valid fine-grained scope should decode");
    let fine_grained = decoded
        .fine_grained_scopes()
        .expect("fine-grained discriminator carries a payload");

    // Then every allow-list remains attached to its declared resource boundary.
    assert_eq!(decoded.scope_type(), TokenScopeType::FineGrained);
    assert_eq!(fine_grained.resource_selection, ResourceSelection::Selected);
    assert_eq!(
        fine_grained.selected_resources,
        vec!["document:doc_1".to_string(), "document:doc_2".to_string()]
    );
    assert_eq!(
        fine_grained.resource_permissions["document"],
        vec!["document:read".to_string(), "document:write".to_string()]
    );
    assert_eq!(
        fine_grained.org_permissions["org_123"],
        vec!["organization:manage".to_string()]
    );
}

#[test]
fn given_all_resource_selection_when_selected_resources_are_present_then_decoding_rejects_it() {
    // Given an all-resources token with a contradictory explicit resource list.
    let error = token_scope_error(serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_selection": "all",
            "selected_resources": ["document:doc_1"]
        }
    }));

    // Then the selection mode cannot silently broaden or narrow the wrong set.
    assert!(error.contains("resource_selection=all cannot include selected_resources"));
}

#[test]
fn given_selected_resource_selection_when_resources_are_empty_then_decoding_rejects_it() {
    // Given a selected-resources token with no selected resource identifiers.
    let error = token_scope_error(serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {"resource_selection": "selected"}
    }));

    // Then selected mode always has an explicit non-empty allow-list.
    assert!(error.contains("resource_selection=selected requires selected_resources"));
}

#[test]
fn given_explicit_full_access_when_restricted_fields_are_present_then_decoding_rejects_them() {
    // Given the unrestricted discriminator paired with each restricted field
    // family.
    let payloads = [
        serde_json::json!({
            "scope_type": "full_access",
            "scope_strings": ["document:read"]
        }),
        serde_json::json!({
            "scope_type": "full_access",
            "fine_grained": {}
        }),
        serde_json::json!({
            "scope_type": "full_access",
            "resolved_permissions": ["document:read"]
        }),
    ];

    // When each ambiguous payload is decoded.
    for payload in payloads {
        let error = token_scope_error(payload);

        // Then full access never silently ignores a restriction.
        assert!(error.contains("full_access token scope cannot include restricted scope fields"));
    }
}

#[test]
fn given_scope_strings_when_fine_grained_fields_are_present_then_decoding_rejects_them() {
    // Given coarse scope strings paired with a fine-grained payload.
    let error = token_scope_error(serde_json::json!({
        "scope_type": "scope_strings",
        "scope_strings": ["document:read"],
        "fine_grained": {}
    }));

    // Then the discriminator cannot be used to reinterpret the payload.
    assert!(error.contains("scope_strings token scope cannot include fine_grained fields"));
}

#[test]
fn given_scope_strings_when_resolved_ceiling_has_no_requested_scopes_then_decoding_rejects_it() {
    // Given a derived ceiling without the source scope strings it summarizes.
    let error = token_scope_error(serde_json::json!({
        "scope_type": "scope_strings",
        "resolved_permissions": ["document:read"]
    }));

    // Then a persisted ceiling cannot become detached from its requested scope.
    assert!(error.contains("resolved_permissions requires non-empty scope_strings"));
}

#[test]
fn given_fine_grained_scope_when_coarse_fields_are_present_then_decoding_rejects_each_conflict() {
    // Given a fine-grained discriminator paired with each mutually exclusive
    // field.
    let payloads = [
        serde_json::json!({
            "scope_type": "fine_grained",
            "scope_strings": ["document:read"]
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "resolved_permissions": ["document:read"]
        }),
    ];

    // When each conflicting representation is decoded.
    let errors = payloads
        .into_iter()
        .map(token_scope_error)
        .collect::<Vec<_>>();

    // Then fine-grained scopes cannot inherit a coarse or derived ceiling.
    assert!(errors[0].contains("fine_grained token scope cannot include scope_strings fields"));
    assert!(errors[1].contains("fine_grained token scope cannot include resolved_permissions"));
}

#[test]
fn given_restricted_fields_when_scope_type_is_omitted_then_decoding_rejects_ambiguous_input() {
    // Given each restricted field family without its discriminator.
    let payloads = [
        serde_json::json!({"scope_strings": ["document:read"]}),
        serde_json::json!({"fine_grained": {}}),
        serde_json::json!({"resolved_permissions": ["document:read"]}),
    ];

    // When the decoder infers the scope type from the fields.
    for payload in payloads {
        let error = token_scope_error(payload);

        // Then restricted credentials require an explicit, auditable
        // discriminator.
        assert!(error.contains("scope_type is required when restricted scope fields are present"));
    }
}

#[test]
fn given_resolved_permissions_when_empty_or_duplicate_then_decoding_rejects_the_ceiling() {
    // Given an empty ceiling and a ceiling with repeated permission ids.
    let payloads = [
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": ["document:read"],
            "resolved_permissions": []
        }),
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": ["document:read"],
            "resolved_permissions": ["document:read", "document:read"]
        }),
    ];

    // When each malformed ceiling is decoded.
    let errors = payloads
        .into_iter()
        .map(token_scope_error)
        .collect::<Vec<_>>();

    // Then empty and ambiguous permission ceilings fail before authorization.
    assert!(errors[0].contains("resolved_permissions must contain at least one permission"));
    assert!(errors[1].contains("resolved_permissions must not contain duplicates"));
}

#[test]
fn given_scope_strings_when_entries_are_empty_or_too_long_then_decoding_rejects_them() {
    // Given malformed scope strings at both validation edges.
    let payloads = [
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": [""]
        }),
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": ["x".repeat(129)]
        }),
    ];

    // When each scope list crosses the bounded-string decoder.
    for payload in payloads {
        let error = token_scope_error(payload);

        // Then empty and oversized user-controlled values are rejected.
        assert!(error.contains("string entries must be 1..=128 bytes"));
    }
}

#[test]
fn given_resource_identifiers_when_empty_or_too_long_then_decoding_rejects_them() {
    // Given malformed selected-resource and organization identifiers.
    let payloads = [
        (
            serde_json::json!({
                "scope_type": "fine_grained",
                "fine_grained": {"selected_resources": [""]}
            }),
            "string entries must be 1..=58 bytes",
        ),
        (
            serde_json::json!({
                "scope_type": "fine_grained",
                "fine_grained": {"selected_resources": ["x".repeat(59)]}
            }),
            "string entries must be 1..=58 bytes",
        ),
        (
            serde_json::json!({"scope_type": "full_access", "org_id": ""}),
            "identifiers must be 1..=58 bytes",
        ),
        (
            serde_json::json!({
                "scope_type": "full_access",
                "org_id": "x".repeat(59)
            }),
            "identifiers must be 1..=58 bytes",
        ),
    ];

    // When each identifier crosses its owning bounded decoder.
    for (payload, expected_error) in payloads {
        let error = token_scope_error(payload);

        // Then identifiers cannot be empty or exceed the key-size budget.
        assert!(error.contains(expected_error));
    }
}

#[test]
fn given_permission_map_when_key_or_value_is_invalid_then_decoding_rejects_it() {
    // Given an invalid map key and invalid permission values.
    let payloads = [
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {"resource_permissions": {"": ["document:read"]}}
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {
                "resource_permissions": {"document": [""]}
            }
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {
                "org_permissions": {"org_123": ["x".repeat(129)]}
            }
        }),
    ];

    // When each malformed map crosses the bounded map decoder.
    for payload in payloads {
        let error = token_scope_error(payload);

        // Then map keys and values obey their distinct bounded string
        // contracts.
        assert!(
            error.contains("map keys must be 1..=58 bytes")
                || error.contains("string entries must be 1..=128 bytes")
        );
    }
}

#[test]
fn given_unknown_token_scope_fields_when_decoding_then_boundary_rejects_them() {
    // Given unknown fields at both the token and fine-grained payload levels.
    let payloads = [
        r#"{"scope_type":"full_access","unknown":true}"#,
        r#"{"scope_type":"fine_grained","fine_grained":{"unknown":true}}"#,
    ];

    // When raw JSON crosses the strict wire decoder.
    for payload in payloads {
        let error = token_scope_json_error(payload);

        // Then schema drift cannot be silently ignored at an authorization
        // boundary.
        assert!(error.contains("unknown field"));
    }
}

#[test]
fn given_duplicate_permission_map_keys_when_decoding_raw_json_then_boundary_rejects_them() {
    // Given duplicate keys in each permission-map family (Value-based tests
    // cannot preserve them).
    let payloads = [
        r#"{"scope_type":"fine_grained","fine_grained":{"resource_permissions":{"document":["document:read"],"document":["document:write"]}}}"#,
        r#"{"scope_type":"fine_grained","fine_grained":{"org_permissions":{"org_123":["organization:read"],"org_123":["organization:write"]}}}"#,
    ];

    // When raw JSON is decoded through MapAccess.
    for payload in payloads {
        let error = token_scope_json_error(payload);

        // Then duplicate policy keys cannot create parser-dependent
        // authorization.
        assert!(error.contains("permission maps must not contain duplicate keys"));
    }
}

#[test]
fn given_non_collection_scope_fields_when_decoding_then_shape_validation_rejects_them() {
    // Given each bounded collection represented by the wrong JSON shape.
    let payloads = [
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": {"scope": "document:read"}
        }),
        serde_json::json!({
            "scope_type": "scope_strings",
            "scope_strings": ["document:read"],
            "resolved_permissions": {"permission": "document:read"}
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {"selected_resources": "document:doc_1"}
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {"resource_permissions": []}
        }),
        serde_json::json!({
            "scope_type": "fine_grained",
            "fine_grained": {"org_permissions": []}
        }),
    ];

    // When untrusted shapes cross the deserialization boundary.
    for payload in payloads {
        let error = token_scope_error(payload);

        // Then the bounded visitors reject shapes that are not collections.
        assert!(
            error.contains("expected a bounded string sequence")
                || error.contains("expected a bounded string map")
        );
    }
}

#[test]
fn given_scope_collections_when_each_limit_is_exact_then_decoding_accepts_them() {
    // Given maximum-sized collections in their owning scope family.
    let scope_strings = (0..200)
        .map(|index| format!("document:{index}"))
        .collect::<Vec<_>>();
    let selected_resources = (0..1_000)
        .map(|index| format!("document:doc_{index}"))
        .collect::<Vec<_>>();
    let permission_values = (0..500)
        .map(|index| format!("document:permission_{index}"))
        .collect::<Vec<_>>();
    let resource_permissions = (0..1_000)
        .map(|index| {
            (
                format!("resource_{index}"),
                vec!["document:read".to_string()],
            )
        })
        .collect::<HashMap<_, _>>();

    // When each bounded collection is decoded in a valid representation.
    let coarse = serde_json::json!({
        "scope_type": "scope_strings",
        "scope_strings": scope_strings
    });
    let fine = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {
            "resource_selection": "selected",
            "selected_resources": selected_resources,
            "resource_permissions": resource_permissions,
            "org_permissions": {"org_123": permission_values}
        }
    });
    let decoded_coarse = serde_json::from_value::<TokenScopeConfig>(coarse)
        .expect("maximum coarse scope list should decode");
    let decoded_fine = serde_json::from_value::<TokenScopeConfig>(fine)
        .expect("maximum fine-grained scope collections should decode");

    // Then every exact limit is accepted without an off-by-one rejection.
    assert_eq!(decoded_coarse.scope_strings().len(), 200);
    let fine_grained = decoded_fine
        .fine_grained_scopes()
        .expect("fine-grained payload should be present");
    assert_eq!(fine_grained.selected_resources.len(), 1_000);
    assert_eq!(fine_grained.resource_permissions.len(), 1_000);
    assert_eq!(fine_grained.org_permissions["org_123"].len(), 500);
}

#[test]
fn given_permission_map_when_entry_count_exceeds_limit_then_decoding_rejects_it() {
    // Given one more resource bucket than the bounded map permits.
    let resource_permissions = (0..=1_000)
        .map(|index| {
            (
                format!("resource_{index}"),
                vec!["document:read".to_string()],
            )
        })
        .collect::<HashMap<_, _>>();
    let payload = serde_json::json!({
        "scope_type": "fine_grained",
        "fine_grained": {"resource_permissions": resource_permissions}
    });

    // When the map crosses the deserialization boundary.
    let error = token_scope_error(payload);

    // Then unbounded resource buckets cannot consume arbitrary memory.
    assert!(error.contains("map exceeds maximum of 1000 entries"));
}
