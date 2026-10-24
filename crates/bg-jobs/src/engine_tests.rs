use std::num::NonZeroU16;

use crate::{DriveRequest, DriveRequestInput, MonotonicDeadline, QueueSelection, Timestamp};

fn assert_send<T: Send>(_: T) {}

#[test]
fn given_a_job_system_when_driving_then_the_future_is_send() {
    let system = crate::test_helper::system(
        crate::FakeStore::local(),
        crate::FairnessPolicy::low_volume(),
        1,
    );
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: 1.try_into().expect("claim limit is non-zero"),
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: 1.try_into().expect("payload limit is non-zero"),
        max_completion_details: 0,
        max_store_operations: 1.try_into().expect("operation limit is non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(2),
    })
    .expect("drive request is valid");

    assert_send(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO));
}

#[test]
fn given_a_near_maximum_clock_when_executing_claim_then_deadline_overflow_is_rejected() {
    let system = crate::test_helper::system(
        crate::FakeStore::local(),
        crate::FairnessPolicy::low_volume(),
        1,
    );
    crate::test_helper::block_on(system.enqueue_raw(
        crate::test_helper::low_volume_job(92, Timestamp::ZERO),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim =
        crate::test_helper::block_on(system.claim(crate::JobId::from([92; 16]), Timestamp::ZERO))
            .expect("claim commits");
    assert!(matches!(
        crate::test_helper::block_on(system.execute_claimed(&claim, Timestamp::ZERO, || {
            MonotonicDeadline::from_nanos(u64::MAX - 1)
        },)),
        Err(crate::JobSystemError::Validation(
            crate::ValidationError::Overflow { .. }
        ))
    ));
}

#[test]
fn given_an_expired_claim_when_executing_then_handler_is_rejected() {
    let system = crate::test_helper::system(
        crate::FakeStore::local(),
        crate::FairnessPolicy::low_volume(),
        1,
    );
    crate::test_helper::block_on(system.enqueue_raw(
        crate::test_helper::low_volume_job(93, Timestamp::ZERO),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim =
        crate::test_helper::block_on(system.claim(crate::JobId::from([93; 16]), Timestamp::ZERO))
            .expect("claim commits");
    assert!(matches!(
        crate::test_helper::block_on(system.execute_claimed(
            &claim,
            Timestamp::from_millis(2000),
            || MonotonicDeadline::ZERO,
        )),
        Err(crate::JobSystemError::LeaseLost)
    ));
}
