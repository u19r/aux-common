use crate::{
    test_helper::{block_on, low_volume_job, system},
    *,
};

#[test]
fn given_scheduled_job_when_suspended_and_resumed_then_identity_schedule_and_checkpoint_survive() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    let seed = low_volume_job(1, Timestamp::ZERO);
    block_on(system.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(5),
            checkpoint: bytes::Bytes::from_static(b"cursor"),
        },
        Timestamp::from_millis(1),
    ))
    .unwrap();
    let before = read_record(&system, id);
    block_on(system.suspend_job(id)).unwrap();
    let suspended = read_record(&system, id);
    assert_eq!(suspended.state, JobState::Suspended);
    assert_eq!(suspended.execution_id, before.execution_id);
    assert_eq!(suspended.scheduled_at, before.scheduled_at);
    assert_eq!(suspended.checkpoint, before.checkpoint);
    assert!(matches!(
        block_on(system.claim(id, Timestamp::from_millis(10))),
        Err(JobSystemError::LeaseConflict)
    ));
    let snapshot = store.snapshot().unwrap();
    block_on(system.suspend_job(id)).unwrap();
    assert_eq!(
        block_on(system.ensure_seed_raw(seed, Timestamp::from_millis(10)))
            .unwrap()
            .disposition,
        EnqueueDisposition::AlreadyPresent
    );
    assert_eq!(store.snapshot().unwrap(), snapshot);
    block_on(system.resume_job(id)).unwrap();
    let resumed = read_record(&system, id);
    assert_eq!(resumed.execution_id, before.execution_id);
    assert_eq!(resumed.scheduled_at, before.scheduled_at);
    assert_eq!(resumed.checkpoint, before.checkpoint);
    let next = block_on(system.claim(id, Timestamp::from_millis(10))).unwrap();
    assert!(next.context().unwrap().effect_authority().is_ok());
}

#[test]
fn given_leased_or_cancelled_job_when_suspension_is_requested_then_work_is_not_reactivated() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    block_on(system.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(matches!(
        block_on(system.suspend_job(id)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(matches!(
        block_on(system.resume_job(id)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(store.snapshot().unwrap(), snapshot);
    block_on(system.request_job_cancellation(&claim, Timestamp::ZERO)).unwrap();
    block_on(system.cancel_claim(claim, Timestamp::ZERO)).unwrap();
    assert!(matches!(
        block_on(system.resume_job(id)),
        Err(JobSystemError::LeaseConflict)
    ));
}

#[test]
fn given_suspended_job_when_cancelled_then_resume_cannot_restore_it() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([3; 16]);
    block_on(system.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    block_on(system.suspend_job(id)).unwrap();
    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::ZERO)).unwrap(),
        CancellationResult::Cancelled
    );
    assert_eq!(read_record(&system, id).state, JobState::Cancelled);
    assert!(matches!(
        block_on(system.resume_job(id)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(matches!(
        block_on(system.claim(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
}

fn read_record(system: &JobSystem<FakeStore>, id: JobId) -> JobRecordV1 {
    let value = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).unwrap()),
    )
    .unwrap()
    .unwrap();
    crate::codec::decode_job_record(&value).unwrap()
}

#[test]
fn given_suspended_job_with_missing_or_corrupt_marker_when_resumed_or_cancelled_then_fence_is_not_reset()
 {
    for marker in [None, Some(bytes::Bytes::from_static(b"corrupt"))] {
        let store = FakeStore::local();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = suspend_claimed_job(&system);
        let key = crate::keys::operation_key(system.namespace(), &id).unwrap();
        let (_, fence) = read_marker(&system, id);
        assert!(fence > 0);
        match marker {
            Some(marker) => store.put_raw(key, marker).unwrap(),
            None => {
                assert!(store.delete_raw(&key).unwrap());
            }
        }
        let snapshot = store.snapshot().unwrap();
        assert!(matches!(
            block_on(system.resume_job(id)),
            Err(JobSystemError::PayloadCorrupt)
        ));
        assert!(matches!(
            block_on(system.cancel_job(id, Timestamp::ZERO)),
            Err(JobSystemError::PayloadCorrupt)
        ));
        assert_eq!(store.snapshot().unwrap(), snapshot);
        assert_eq!(read_record(&system, id).state, JobState::Suspended);
    }
}

#[test]
fn given_suspended_claimed_job_when_cancelled_then_operation_advances_and_fence_high_water_survives()
 {
    let store = FakeStore::local();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = suspend_claimed_job(&system);
    let (before_operation, before_fence) = read_marker(&system, id);
    block_on(system.cancel_job(id, Timestamp::ZERO)).unwrap();
    let (after_operation, after_fence) = read_marker(&system, id);
    assert_ne!(after_operation, before_operation);
    assert!(before_fence > 0);
    assert_eq!(after_fence, before_fence);
    assert_eq!(read_record(&system, id).state, JobState::Cancelled);
}

fn suspend_claimed_job(system: &JobSystem<FakeStore>) -> JobId {
    let id = JobId::from([4; 16]);
    block_on(system.enqueue_raw(low_volume_job(4, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(5),
            checkpoint: bytes::Bytes::from_static(b"cursor"),
        },
        Timestamp::from_millis(1),
    ))
    .unwrap();
    block_on(system.suspend_job(id)).unwrap();
    id
}

fn read_marker(system: &JobSystem<FakeStore>, id: JobId) -> (OperationId, u64) {
    let value = block_on(
        system
            .store()
            .get(crate::keys::operation_key(system.namespace(), &id).unwrap()),
    )
    .unwrap()
    .unwrap();
    crate::keys::decode_active_operation(&value, &id).unwrap()
}
