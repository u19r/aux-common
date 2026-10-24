use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;

use super::checkpoint::ClaimCheckpoint;
use crate::{
    drive::scheduler::DriveClock,
    test_helper::{block_on, low_volume_job, system},
    *,
};

#[test]
fn given_an_expired_runtime_claim_when_handler_saves_checkpoint_then_state_is_preserved() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(94, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim =
        block_on(system.claim(JobId::from([94; 16]), Timestamp::ZERO)).expect("claim commits");
    let nanos = Arc::new(AtomicU64::new(0));
    let sample = Arc::clone(&nanos);
    let clock = DriveClock::new(
        move || MonotonicDeadline::from_nanos(sample.load(Ordering::SeqCst)),
        Timestamp::ZERO,
    );
    let before = store.snapshot().expect("snapshot succeeds");
    let mut owner = ClaimCheckpoint {
        system: &system,
        claim: &mut claim,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
        clock,
    };
    let mut execution = JobExecution::new(&mut owner);
    nanos.store(2_000_000_000, Ordering::SeqCst);
    let error = block_on(execution.save_checkpoint(Bytes::from_static(b"expired")))
        .expect_err("expired checkpoint is rejected");
    assert!(matches!(
        error.downcast_ref::<JobSystemError<FakeStoreError>>(),
        Some(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_renewal_loss_when_handler_saves_checkpoint_then_state_is_preserved() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(95, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim =
        block_on(system.claim(JobId::from([95; 16]), Timestamp::ZERO)).expect("claim commits");
    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::from_millis(2000))),
        Err(JobSystemError::LeaseLost)
    ));
    let before = store.snapshot().expect("snapshot succeeds");
    let mut owner = ClaimCheckpoint {
        system: &system,
        claim: &mut claim,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
        clock: DriveClock::new(|| MonotonicDeadline::ZERO, Timestamp::ZERO),
    };
    let mut execution = JobExecution::new(&mut owner);
    let error = block_on(execution.save_checkpoint(Bytes::from_static(b"renewal-lost")))
        .expect_err("checkpoint after renewal loss is rejected");
    assert!(matches!(
        error.downcast_ref::<JobSystemError<FakeStoreError>>(),
        Some(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}
