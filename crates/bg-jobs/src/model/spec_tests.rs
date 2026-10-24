use std::{num::NonZeroU16, time::Duration};

use bytes::Bytes;

use crate::{
    EffectMode, FairnessPolicy, JobCatalog, JobKind, JobSpec, QueueName, RetryPreset,
    RetrySelection, Timestamp, test_helper::CompletingHandler,
};

#[test]
fn given_a_complete_spec_when_registering_then_it_returns_a_typed_handle() {
    let spec = JobSpec::new(
        JobKind::try_new("typed.test").expect("kind"),
        NonZeroU16::MIN,
        QueueName::try_new("default").expect("queue"),
        CompletingHandler,
        |value: &u64| Ok(Bytes::from(value.to_be_bytes().to_vec())),
    )
    .policy(
        EffectMode::Idempotent,
        FairnessPolicy::low_volume(),
        RetrySelection::Preset(RetryPreset::Interactive),
        Duration::from_secs(1),
    );

    let mut catalog = JobCatalog::new();
    let handle = catalog.register(spec).expect("spec is valid");

    assert_eq!(handle.kind().as_str(), "typed.test");
    assert_eq!(handle.schema_version(), NonZeroU16::MIN);
}

#[test]
fn given_encoded_payload_when_using_bytes_spec_then_registration_needs_no_codec() {
    let spec = JobSpec::bytes(
        JobKind::try_new("typed.bytes").expect("kind"),
        NonZeroU16::MIN,
        QueueName::try_new("default").expect("queue"),
        CompletingHandler,
    )
    .policy(
        EffectMode::Fenced,
        FairnessPolicy::low_volume(),
        RetrySelection::Preset(RetryPreset::Network),
        Duration::from_secs(1),
    );

    let mut catalog = JobCatalog::new();
    let handle = catalog.register(spec).expect("spec is valid");

    assert_eq!(handle.kind().as_str(), "typed.bytes");
}

#[test]
fn given_enqueue_options_when_built_then_defaults_are_safe_and_explicit_values_survive() {
    let fairness = crate::FairnessClass::low_volume();
    let options = crate::EnqueueOptions::new(fairness)
        .scheduled_at(Timestamp::from_millis(10))
        .expires_at(Timestamp::from_millis(20))
        .retry(RetrySelection::Preset(RetryPreset::Maintenance));

    assert_eq!(
        options.scheduled_at_value(),
        Some(Timestamp::from_millis(10))
    );
    assert_eq!(options.expires_at_value(), Some(Timestamp::from_millis(20)));
    assert_eq!(
        options.retry_override(),
        Some(RetrySelection::Preset(RetryPreset::Maintenance))
    );
}

#[test]
fn given_missing_policy_when_registering_then_the_catalog_rejects_the_spec() {
    let spec = JobSpec::new(
        JobKind::try_new("typed.missing").expect("kind"),
        NonZeroU16::MIN,
        QueueName::try_new("default").expect("queue"),
        CompletingHandler,
        |value: &u64| Ok(Bytes::from(value.to_be_bytes().to_vec())),
    );

    let mut catalog = JobCatalog::new();
    let result = catalog.register(spec);

    assert!(matches!(
        result,
        Err(crate::ValidationError::InvalidValue {
            field: "handler effect mode"
        })
    ));
}
