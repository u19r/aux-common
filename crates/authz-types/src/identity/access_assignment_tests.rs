use serde_json::json;

use crate::{
    AccessAssignmentDurationSeconds, AccessAssignmentExplanation, AccessAssignmentMode,
    AccessAssignmentPolicy, AccessAssignmentPolicySpec, AccessAssignmentRemovalCause,
    AccessAssignmentRemovalSource, AccessAssignmentStatus, AccessAssignmentTarget,
    MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS, MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES,
    MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS, ValidationError,
};

fn build_bounded_duration(value: u32) -> AccessAssignmentDurationSeconds {
    AccessAssignmentDurationSeconds::try_new(value).expect("test duration should be bounded")
}

fn build_permanent_spec() -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec::try_new(AccessAssignmentMode::PermanentOrTemporary, None)
        .expect("permanent policy should be valid")
}

fn build_temporary_spec(maximum: u32) -> AccessAssignmentPolicySpec {
    AccessAssignmentPolicySpec::try_new(
        AccessAssignmentMode::TemporaryRequired,
        Some(build_bounded_duration(maximum)),
    )
    .expect("temporary policy should be valid")
}

fn assert_wire_name(value: impl serde::Serialize, expected: &str) {
    assert_eq!(
        serde_json::to_value(value).expect("serialize enum"),
        json!(expected)
    );
}

#[test]
fn given_boundary_durations_when_constructed_then_values_and_expiry_are_exact() {
    // Given a duration at each supported boundary.
    let minimum = build_bounded_duration(MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS);
    let maximum = build_bounded_duration(MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS);

    // When the duration is inspected and applied to a trusted timestamp.
    let expiry = minimum
        .checked_expires_at_millis(1_234)
        .expect("bounded duration should produce an expiry");

    // Then the value remains whole seconds and the expiry uses milliseconds.
    assert_eq!(minimum.get(), MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS);
    assert_eq!(maximum.get(), MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS);
    assert_eq!(expiry, 901_234);
}

#[test]
fn given_duration_outside_bounds_when_constructed_then_validation_error_identifies_field() {
    // Given values immediately outside the inclusive duration range.
    let below_minimum = MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS - 1;
    let above_maximum = MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS + 1;

    // When each value is validated.
    let errors = [below_minimum, above_maximum].map(|value| {
        AccessAssignmentDurationSeconds::try_new(value).expect_err("out-of-range value")
    });

    // Then both failures identify the duration boundary.
    for error in errors {
        assert!(matches!(
            error,
            ValidationError::OutOfRange {
                field: "duration_seconds",
                ..
            }
        ));
    }
}

#[test]
fn given_expiry_near_integer_limit_when_computed_then_overflow_is_rejected() {
    // Given a valid duration and a timestamp with no room for its addition.
    let duration = build_bounded_duration(MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS);

    // When expiry arithmetic would exceed the trusted timestamp type.
    let error = duration
        .checked_expires_at_millis(i64::MAX)
        .expect_err("expiry overflow must be rejected");

    // Then the arithmetic failure is explicit and typed.
    assert_eq!(
        error,
        ValidationError::OutOfRange {
            field: "duration_seconds",
            message: "expiry arithmetic overflowed".to_string(),
        }
    );
}

#[test]
fn given_valid_duration_when_serialized_and_deserialized_then_bounded_value_round_trips() {
    // Given a valid duration value.
    let duration = build_bounded_duration(3_600);

    // When it crosses the JSON boundary and an invalid value is attempted.
    let encoded = serde_json::to_value(duration).expect("serialize duration");
    let decoded = serde_json::from_value::<AccessAssignmentDurationSeconds>(encoded)
        .expect("deserialize duration");
    let invalid = serde_json::from_value::<AccessAssignmentDurationSeconds>(json!(899));

    // Then the valid value is preserved and the invalid wire value is rejected.
    assert_eq!(decoded, duration);
    assert_eq!(
        serde_json::to_value(duration).expect("serialize duration"),
        json!(3_600)
    );
    assert!(invalid.is_err());
}

#[test]
fn given_invalid_explanation_when_constructed_then_validation_error_is_specific() {
    // Given empty, oversized, and control-character explanations.
    let empty = AccessAssignmentExplanation::try_new(" \t ")
        .expect_err("empty explanation must be rejected");
    let oversized = AccessAssignmentExplanation::try_new(
        "x".repeat(MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES + 1),
    )
    .expect_err("oversized explanation must be rejected");
    let controls = AccessAssignmentExplanation::try_new("INC\n4832")
        .expect_err("control characters must be rejected");

    // When each validation error is classified.
    // Then each invalid explanation reports its owning boundary.
    assert_eq!(empty, ValidationError::RequiredFieldMissing("explanation"));
    assert!(matches!(
        oversized,
        ValidationError::OutOfRange {
            field: "explanation",
            ..
        }
    ));
    assert!(matches!(
        controls,
        ValidationError::InvalidFormat {
            field: "explanation",
            ..
        }
    ));
}

#[test]
fn given_trimmed_explanation_when_serialized_and_deserialized_then_normalized_value_round_trips() {
    // Given an explanation whose surrounding whitespace should be normalized.
    let explanation = AccessAssignmentExplanation::try_new("  INC-4832  ").expect("explanation");

    // When the normalized explanation crosses the JSON boundary.
    let encoded = serde_json::to_value(&explanation).expect("serialize explanation");
    let decoded = serde_json::from_value::<AccessAssignmentExplanation>(encoded)
        .expect("deserialize explanation");
    let invalid = serde_json::from_value::<AccessAssignmentExplanation>(json!(" \n "));

    // Then normalization is retained and invalid wire text is rejected.
    assert_eq!(explanation.as_str(), "INC-4832");
    assert_eq!(decoded, explanation);
    assert_eq!(
        serde_json::to_value(explanation).expect("serialize explanation"),
        json!("INC-4832")
    );
    assert!(invalid.is_err());
}

#[test]
fn given_policy_specs_when_constructed_and_serialized_then_customer_shape_round_trips() {
    // Given permanent and temporary customer-configured specifications.
    let permanent = build_permanent_spec();
    let temporary = build_temporary_spec(3_600);

    // When each specification is serialized and deserialized.
    let permanent_json = serde_json::to_value(&permanent).expect("serialize permanent policy");
    let temporary_json = serde_json::to_value(&temporary).expect("serialize temporary policy");
    let decoded_permanent = serde_json::from_value::<AccessAssignmentPolicySpec>(permanent_json)
        .expect("deserialize permanent policy");
    let decoded_temporary = serde_json::from_value::<AccessAssignmentPolicySpec>(temporary_json)
        .expect("deserialize temporary policy");

    // Then server-owned metadata is absent and both customer shapes round-trip.
    assert_eq!(decoded_permanent, permanent);
    assert_eq!(decoded_temporary, temporary);
    assert_eq!(
        serde_json::to_value(permanent).expect("serialize permanent policy"),
        json!({
            "assignment_mode": "permanent_or_temporary"
        })
    );
}

#[test]
fn given_invalid_policy_spec_when_constructed_or_deserialized_then_rejected() {
    // Given a temporary policy without its required maximum and a policy with
    // unknown data, including both omitted and explicit null maximum values.
    let missing_maximum =
        AccessAssignmentPolicySpec::try_new(AccessAssignmentMode::TemporaryRequired, None)
            .expect_err("temporary policy requires a maximum");
    let missing_maximum_json = serde_json::from_value::<AccessAssignmentPolicySpec>(json!({
        "assignment_mode": "temporary_required"
    }))
    .expect_err("temporary policy JSON requires a maximum");
    let null_maximum_json = serde_json::from_value::<AccessAssignmentPolicySpec>(json!({
        "assignment_mode": "temporary_required",
        "maximum_duration_seconds": null
    }))
    .expect_err("temporary policy JSON rejects a null maximum");
    let unknown_field = serde_json::from_value::<AccessAssignmentPolicySpec>(json!({
        "assignment_mode": "permanent_or_temporary",
        "unexpected": true
    }));

    // When the invalid policy inputs are checked.
    assert_eq!(
        missing_maximum,
        ValidationError::RequiredFieldMissing("maximum_duration_seconds")
    );

    // Then unknown fields cannot enter the customer contract.
    assert!(
        missing_maximum_json
            .to_string()
            .contains("maximum_duration_seconds")
    );
    assert!(
        null_maximum_json
            .to_string()
            .contains("maximum_duration_seconds")
    );
    assert!(unknown_field.is_err());
}

#[test]
fn given_valid_policy_spec_when_materialized_then_server_metadata_starts_at_revision_one() {
    // Given a valid customer policy specification.
    let spec = build_temporary_spec(3_600);

    // When the server materializes persisted policy metadata.
    let policy = AccessAssignmentPolicy::from_spec(&spec, 10_000, "admin".to_string())
        .expect("materialize policy");

    // Then revision and provenance are server-owned and validation succeeds.
    assert_eq!(policy.revision, 1);
    assert_eq!(policy.updated_at_ms, 10_000);
    assert_eq!(policy.updated_by.as_deref(), Some("admin"));
    assert!(policy.validate().is_ok());
}

#[test]
fn given_matching_policy_spec_when_updated_then_existing_metadata_is_preserved() {
    // Given a persisted policy and the same desired specification.
    let spec = build_permanent_spec();
    let policy = AccessAssignmentPolicy::from_spec(&spec, 10_000, "first-admin".to_string())
        .expect("materialize policy");

    // When the desired policy is applied again with different metadata.
    let unchanged = policy
        .updated_for_spec(&spec, 20_000, "second-admin".to_string())
        .expect("matching policy should not update");

    // Then the existing revision and provenance remain stable.
    assert_eq!(unchanged, policy);
}

#[test]
fn given_changed_policy_spec_when_updated_then_revision_and_metadata_advance() {
    // Given a permanent policy and a changed temporary policy specification.
    let original_spec = build_permanent_spec();
    let changed_spec = build_temporary_spec(7_200);
    let policy =
        AccessAssignmentPolicy::from_spec(&original_spec, 10_000, "first-admin".to_string())
            .expect("materialize policy");

    // When the changed specification is applied.
    let updated = policy
        .updated_for_spec(&changed_spec, 20_000, "second-admin".to_string())
        .expect("changed policy should update");

    // Then revision, policy values, and provenance all advance together.
    assert_eq!(updated.revision, 2);
    assert_eq!(
        updated.maximum_duration_seconds,
        Some(build_bounded_duration(7_200))
    );
    assert_eq!(updated.updated_at_ms, 20_000);
    assert_eq!(updated.updated_by.as_deref(), Some("second-admin"));
    assert!(!updated.matches_spec(&original_spec));
}

#[test]
fn given_revision_at_integer_limit_when_updated_for_changed_spec_then_overflow_is_rejected() {
    // Given a valid policy whose revision cannot be incremented.
    let policy = AccessAssignmentPolicy::try_new(
        AccessAssignmentMode::PermanentOrTemporary,
        None,
        u64::MAX,
        10_000,
        Some("admin".to_string()),
    )
    .expect("maximum revision is still positive");
    let changed_spec = build_temporary_spec(3_600);

    // When a changed specification would require the overflowing revision.
    let error = policy
        .updated_for_spec(&changed_spec, 20_000, "admin".to_string())
        .expect_err("revision overflow must be rejected");

    // Then the persisted revision remains protected by a typed error.
    assert!(matches!(
        error,
        ValidationError::OutOfRange {
            field: "revision",
            ..
        }
    ));
}

#[test]
fn given_policy_duration_when_validated_then_mode_and_maximum_are_enforced() {
    // Given a temporary policy with a strict maximum and a permanent policy.
    let temporary = AccessAssignmentPolicy::from_spec(
        &build_temporary_spec(3_600),
        10_000,
        "admin".to_string(),
    )
    .expect("temporary policy");
    let permanent =
        AccessAssignmentPolicy::from_spec(&build_permanent_spec(), 10_000, "admin".to_string())
            .expect("permanent policy");

    // When missing, excessive, bounded, and unrestricted durations are checked.
    let missing = temporary
        .validate_duration(None)
        .expect_err("temporary policy requires a duration");
    let excessive = temporary
        .validate_duration(Some(build_bounded_duration(3_601)))
        .expect_err("duration above maximum must be rejected");

    // Then only the invalid temporary requests fail.
    assert!(matches!(
        missing,
        ValidationError::InvalidFormat {
            field: "duration_seconds",
            ..
        }
    ));
    assert!(matches!(
        excessive,
        ValidationError::OutOfRange {
            field: "duration_seconds",
            ..
        }
    ));
    assert!(
        temporary
            .validate_duration(Some(build_bounded_duration(3_600)))
            .is_ok()
    );
    assert!(permanent.validate_duration(None).is_ok());
    assert!(
        permanent
            .validate_duration(Some(build_bounded_duration(
                MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS
            )))
            .is_ok()
    );
}

#[test]
fn given_invalid_persisted_policy_when_deserialized_then_invariants_are_rejected() {
    // Given persisted policy payloads that violate the in-memory invariants.
    let missing_maximum = json!({
        "assignment_mode": "temporary_required",
        "revision": 1,
        "updated_at_ms": 10_000,
        "updated_by": "admin"
    });
    let null_maximum = json!({
        "assignment_mode": "temporary_required",
        "maximum_duration_seconds": null,
        "revision": 1,
        "updated_at_ms": 10_000,
        "updated_by": "admin"
    });
    let zero_revision = json!({
        "assignment_mode": "permanent_or_temporary",
        "maximum_duration_seconds": null,
        "revision": 0,
        "updated_at_ms": 10_000,
        "updated_by": "admin"
    });

    // When persisted JSON is decoded at the shared type boundary.
    let missing_error = serde_json::from_value::<AccessAssignmentPolicy>(missing_maximum)
        .expect_err("temporary persisted policy must require a maximum");
    let null_error = serde_json::from_value::<AccessAssignmentPolicy>(null_maximum)
        .expect_err("temporary persisted policy must reject a null maximum");
    let zero_error = serde_json::from_value::<AccessAssignmentPolicy>(zero_revision)
        .expect_err("persisted policy revision must be positive");

    // Then invalid policy state cannot be reconstructed from storage.
    assert!(
        missing_error
            .to_string()
            .contains("maximum_duration_seconds")
    );
    assert!(null_error.to_string().contains("maximum_duration_seconds"));
    assert!(zero_error.to_string().contains("revision"));
}

#[test]
fn given_invalid_policy_when_validated_then_invariants_are_rejected() {
    // Given policy values assembled by an in-process caller.
    let missing_maximum = AccessAssignmentPolicy {
        assignment_mode: AccessAssignmentMode::TemporaryRequired,
        maximum_duration_seconds: None,
        revision: 1,
        updated_at_ms: 10_000,
        updated_by: None,
    };
    let zero_revision = AccessAssignmentPolicy {
        assignment_mode: AccessAssignmentMode::PermanentOrTemporary,
        maximum_duration_seconds: None,
        revision: 0,
        updated_at_ms: 10_000,
        updated_by: None,
    };

    // When the persisted policy invariants are checked.
    let missing_error = missing_maximum
        .validate()
        .expect_err("temporary policy requires a maximum");
    let zero_error = zero_revision
        .validate()
        .expect_err("policy revision must be positive");

    // Then each invalid state reports its owning field.
    assert_eq!(
        missing_error,
        ValidationError::RequiredFieldMissing("maximum_duration_seconds")
    );
    assert!(matches!(
        zero_error,
        ValidationError::OutOfRange {
            field: "revision",
            ..
        }
    ));
}

#[test]
fn given_policy_when_serialized_and_deserialized_then_server_metadata_round_trips() {
    // Given a valid persisted policy with server metadata.
    let spec = build_temporary_spec(3_600);
    let policy = AccessAssignmentPolicy::from_spec(&spec, 10_000, "admin".to_string())
        .expect("materialize policy");

    // When the full persisted shape crosses JSON.
    let encoded = serde_json::to_value(&policy).expect("serialize policy");
    let decoded =
        serde_json::from_value::<AccessAssignmentPolicy>(encoded).expect("deserialize policy");

    // Then customer policy and server metadata are preserved exactly.
    assert_eq!(decoded, policy);
}

#[test]
fn given_assignment_target_variants_when_resource_id_requested_then_prefix_matches_target() {
    // Given every assignable target variant.
    let targets = [
        (
            AccessAssignmentTarget::Role {
                id: "r1".to_string(),
            },
            "role:r1",
        ),
        (
            AccessAssignmentTarget::OrgGroup {
                id: "g1".to_string(),
            },
            "group:g1",
        ),
        (
            AccessAssignmentTarget::AccessProfile {
                id: "p1".to_string(),
            },
            "access_profile:p1",
        ),
    ];

    // When each target is converted to its stable resource identity.
    for (target, expected) in targets {
        // Then the type-specific prefix and identifier are retained.
        assert_eq!(target.resource_id(), expected);
    }
}

#[test]
fn given_assignment_enums_when_serialized_then_wire_names_are_snake_case() {
    // Given lifecycle, removal-cause, and removal-source values.
    let statuses = [
        (AccessAssignmentStatus::Active, "active"),
        (AccessAssignmentStatus::Expired, "expired"),
        (AccessAssignmentStatus::Revoked, "revoked"),
    ];
    let causes = [
        (AccessAssignmentRemovalCause::Expired, "expired"),
        (AccessAssignmentRemovalCause::Manual, "manual"),
        (
            AccessAssignmentRemovalCause::TargetDeleted,
            "target_deleted",
        ),
        (
            AccessAssignmentRemovalCause::PrincipalDeleted,
            "principal_deleted",
        ),
    ];
    let sources = [
        (AccessAssignmentRemovalSource::ExpiryWorker, "expiry_worker"),
        (AccessAssignmentRemovalSource::Api, "api"),
        (AccessAssignmentRemovalSource::Cascade, "cascade"),
    ];

    // When the values are encoded for the wire.
    // Then every public enum keeps its documented snake_case representation.
    for (value, expected) in statuses {
        assert_wire_name(value, expected);
    }
    for (value, expected) in causes {
        assert_wire_name(value, expected);
    }
    for (value, expected) in sources {
        assert_wire_name(value, expected);
    }
}
