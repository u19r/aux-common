use bytes::Bytes;

use super::driver::LifecycleDriver;
use crate::{
    FakeStore, JobId, JobSystem, Timestamp,
    codec::{KeyCodec, KeyTag, decode_job_record},
    model::JobState,
    policy::FairnessPolicy,
    store::JobStore,
    test_helper::{block_on, completion, low_volume_job},
};

fn system(store: FakeStore) -> JobSystem<FakeStore> {
    crate::test_helper::system(store, FairnessPolicy::low_volume(), 1)
}

#[test]
fn enqueue_claim_and_complete_project_real_store_state() {
    let store = FakeStore::distributed();
    let system = system(store.clone());
    let job_id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue crosses the public JobSystem boundary");
    let job_key = KeyCodec::job(system.namespace(), &job_id).expect("job key");
    let encoded = block_on(system.store().get(job_key.clone()))
        .expect("read persisted record")
        .expect("enqueued job exists");
    assert_eq!(
        decode_job_record(&encoded).expect("record decodes").state,
        JobState::Scheduled
    );

    let claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("claim crosses boundary");
    assert!(matches!(claim.record().state, JobState::Leased(_)));
    block_on(system.complete(claim, completion(), Timestamp::ZERO))
        .expect("complete crosses the public boundary");
    let snapshot = store.snapshot().expect("snapshot reads persisted state");
    assert!(!snapshot.iter().any(|(key, _)| {
        KeyCodec::decode(system.namespace(), key)
            .map(|decoded| decoded.tag == KeyTag::Job)
            .unwrap_or(false)
    }));
}

#[test]
fn malformed_record_projection_fails_closed() {
    let store = FakeStore::distributed();
    let system = system(store.clone());
    let job_id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue succeeds");
    let job_key = KeyCodec::job(system.namespace(), &job_id).expect("job key");
    store
        .put_raw(job_key, Bytes::from_static(&[0x7f]))
        .expect("fixture corruption writes");
    assert!(block_on(system.claim(job_id, Timestamp::ZERO)).is_err());
}

#[test]
fn given_incomplete_command_coverage_when_driver_drops_then_it_panics() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _driver = LifecycleDriver::for_deterministic_command_coverage();
    }));

    assert!(result.is_err(), "incomplete command coverage must fail");
}

#[test]
fn given_incomplete_command_coverage_when_unwinding_then_original_panic_survives() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _driver = LifecycleDriver::for_deterministic_command_coverage();
        panic!("original lifecycle failure");
    }));

    let panic = result.expect_err("the original panic must be preserved");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"original lifecycle failure")
    );
}
