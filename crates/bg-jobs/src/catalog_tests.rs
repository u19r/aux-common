use std::{num::NonZeroU16, time::Duration};

use bytes::Bytes;

use crate::{
    EffectMode, EnqueueDisposition, EnqueueOptions, FairnessClass, FairnessPolicy,
    HandlerDefinition, JobCatalog, JobId, JobKind, JobOutcome, JobSpec, JobSystem, Namespace,
    OwnerId, QueueName, RetryPreset, RetrySelection, Timestamp, ValidationError,
    test_helper::{CompletingHandler, block_on, low_volume_job, wake_scheduler},
};

fn definition(kind: &str, schema_version: u16) -> HandlerDefinition<CompletingHandler> {
    HandlerDefinition {
        kind: JobKind::try_new(kind).expect("test kind is valid"),
        schema_version: NonZeroU16::new(schema_version).expect("test schema is non-zero"),
        queue: QueueName::try_new("default").expect("test queue is valid"),
        effect_mode: EffectMode::Idempotent,
        cost_units: NonZeroU16::MIN,
        fairness_policy: FairnessPolicy::low_volume(),
        default_retry: RetrySelection::Preset(RetryPreset::Interactive),
        default_timeout: Duration::from_secs(1),
        handler: CompletingHandler,
    }
}

fn unit_spec(kind: &str) -> JobSpec<(), CompletingHandler> {
    JobSpec::unit(
        JobKind::try_new(kind).expect("test kind is valid"),
        NonZeroU16::MIN,
        QueueName::try_new("default").expect("test queue is valid"),
        CompletingHandler,
    )
    .policy(
        EffectMode::Idempotent,
        FairnessPolicy::low_volume(),
        RetrySelection::Preset(RetryPreset::Interactive),
        Duration::from_secs(1),
    )
}

#[test]
fn given_a_typed_spec_and_seed_when_registering_then_the_catalog_owns_both() {
    let now = Timestamp::from_millis(10);
    let mut catalog = JobCatalog::new();
    let handle = catalog
        .register_seeded(
            unit_spec("typed.seeded"),
            (),
            EnqueueOptions::new(FairnessClass::low_volume()).job_id(JobId::from([7; 16])),
            now,
        )
        .expect("typed registration and seed are valid");

    assert_eq!(handle.kind().as_str(), "typed.seeded");
    let system = JobSystem::new(
        crate::FakeStore::new(),
        catalog,
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([7; OwnerId::BYTE_LENGTH]),
        wake_scheduler(),
    );
    let result = block_on(system.ensure_seeds(now)).expect("seed is ensured");

    assert_eq!(result[0].disposition, EnqueueDisposition::Enqueued);
}

#[test]
fn given_an_invalid_typed_seed_when_registering_then_the_catalog_is_not_partially_mutated() {
    let now = Timestamp::from_millis(10);
    let mut catalog = JobCatalog::new();
    let invalid_options = EnqueueOptions::new(FairnessClass::low_volume())
        .job_id(JobId::from([8; 16]))
        .scheduled_at(now)
        .expires_at(Timestamp::from_millis(9));

    assert!(
        catalog
            .register_seeded(unit_spec("typed.atomic"), (), invalid_options, now)
            .is_err()
    );

    catalog
        .register(unit_spec("typed.atomic"))
        .expect("failed seed must not leave a registration behind");
}

#[test]
fn given_a_catalog_when_adding_a_seed_then_seed_validation_is_preserved() {
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(definition("email", 1), None)
        .expect("registration is valid");

    catalog
        .add_seed_raw(low_volume_job(1, Timestamp::ZERO))
        .expect("matching seed is valid");
    let mut mismatched_seed = low_volume_job(2, Timestamp::ZERO);
    mismatched_seed.kind = JobKind::try_new("billing").expect("test kind is valid");

    assert!(matches!(
        catalog.add_seed_raw(mismatched_seed),
        Err(ValidationError::InvalidValue {
            field: "seed handler identity"
        })
    ));
}

#[test]
fn given_duplicate_handler_definitions_when_registering_then_the_catalog_rejects_the_second() {
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(definition("email", 1), None)
        .expect("first registration is valid");

    let result = catalog.register_raw(definition("email", 1), None);

    assert!(matches!(
        result,
        Err(ValidationError::InvalidValue {
            field: "duplicate handler registration"
        })
    ));
}

#[test]
fn given_a_seed_for_another_handler_when_registering_then_the_catalog_rejects_the_seed() {
    let mut catalog = JobCatalog::new();
    let result = catalog.register_raw(
        definition("billing", 1),
        Some(low_volume_job(1, Timestamp::ZERO)),
    );

    assert!(matches!(
        result,
        Err(ValidationError::InvalidValue {
            field: "seed handler identity"
        })
    ));
}

#[test]
fn given_a_duplicate_seed_id_when_adding_then_the_catalog_rejects_it() {
    let seed = low_volume_job(1, Timestamp::ZERO);
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(definition("email", 1), Some(seed.clone()))
        .expect("catalog registration is valid");

    let result = catalog.add_seed_raw(seed);

    assert!(matches!(
        result,
        Err(ValidationError::InvalidValue {
            field: "duplicate seed job id"
        })
    ));
}

#[test]
fn given_a_continued_seed_when_catalog_ensures_it_then_schedule_and_checkpoint_are_preserved() {
    let seed = low_volume_job(1, Timestamp::ZERO);
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(definition("email", 1), Some(seed.clone()))
        .expect("catalog registration is valid");
    let system = JobSystem::new(
        crate::FakeStore::new(),
        catalog,
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([1; OwnerId::BYTE_LENGTH]),
        wake_scheduler(),
    );

    let first = block_on(system.ensure_seeds(Timestamp::ZERO)).expect("initial seed is created");
    assert_eq!(first[0].disposition, EnqueueDisposition::Enqueued);

    let claim = block_on(system.claim(seed.job_id, Timestamp::ZERO)).expect("seed claim commits");
    block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(10),
            checkpoint: Bytes::from_static(b"page-1"),
        },
        Timestamp::ZERO,
    ))
    .expect("continuation commits");

    let second = block_on(system.ensure_seeds(Timestamp::from_millis(1)))
        .expect("existing seed is reconciled");
    assert_eq!(second[0].disposition, EnqueueDisposition::AlreadyPresent);
    assert_eq!(
        second[0].wake,
        crate::WakeHint::At(Timestamp::from_millis(10))
    );
}

#[test]
fn given_typed_registrations_when_inspecting_the_catalog_then_only_actual_identities_are_returned()
{
    let mut catalog = JobCatalog::new();
    catalog.register(unit_spec("first")).unwrap();
    catalog.register_raw(definition("second", 2), None).unwrap();
    let actual = catalog
        .test_handler_identities()
        .map(|(kind, version)| (kind.as_str(), version.get()))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual,
        std::collections::BTreeSet::from([("first", 1), ("second", 2)])
    );
}
