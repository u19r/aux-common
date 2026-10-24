use crate::{
    FairnessPolicy, FakeStore, JobCatalog, JobSystemBuilder, Namespace, OwnerId,
    StoreContractError, ValidationError,
    test_helper::{registry, wake_scheduler},
};

#[test]
fn given_complete_job_system_inputs_when_building_then_the_system_is_configured() {
    let system = JobSystemBuilder::new(FakeStore::local())
        .catalog(JobCatalog::from_registry(registry(
            FairnessPolicy::low_volume(),
        )))
        .namespace(Namespace::try_new(b"jobs").expect("test namespace is valid"))
        .owner(OwnerId::from([7; OwnerId::BYTE_LENGTH]))
        .scheduler(wake_scheduler())
        .build()
        .expect("complete builder input is valid");

    assert_eq!(system.namespace().as_bytes(), b"jobs");
    assert_eq!(system.owner(), &OwnerId::from([7; OwnerId::BYTE_LENGTH]));
}

#[test]
fn given_a_missing_namespace_when_building_then_validation_rejects_the_input() {
    let result = JobSystemBuilder::new(FakeStore::local())
        .owner(OwnerId::from([7; OwnerId::BYTE_LENGTH]))
        .scheduler(wake_scheduler())
        .build();

    assert!(matches!(
        result,
        Err(ValidationError::InvalidValue {
            field: "job system namespace"
        })
    ));
}

#[test]
fn given_a_local_store_when_building_distributed_then_the_capability_is_rejected() {
    let result = JobSystemBuilder::new(FakeStore::local())
        .namespace(Namespace::try_new(b"jobs").expect("test namespace is valid"))
        .owner(OwnerId::from([7; OwnerId::BYTE_LENGTH]))
        .scheduler(wake_scheduler())
        .build_distributed();

    assert!(matches!(
        result,
        Err(StoreContractError::FalseDistributedClaim)
    ));
}

#[test]
fn given_a_distributed_store_when_building_distributed_then_the_system_is_created() {
    let result = JobSystemBuilder::new(FakeStore::distributed())
        .namespace(Namespace::try_new(b"jobs").expect("test namespace is valid"))
        .owner(OwnerId::from([7; OwnerId::BYTE_LENGTH]))
        .scheduler(wake_scheduler())
        .build_distributed();

    assert!(result.is_ok());
}
