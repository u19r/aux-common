use crate::{
    test_helper::{block_on, low_volume_job, system},
    *,
};

#[test]
fn given_renewal_loss_after_cancellation_when_requesting_again_then_cancellation_is_idempotent() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(97, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim =
        block_on(system.claim(JobId::from([97; 16]), Timestamp::ZERO)).expect("claim commits");
    assert_eq!(
        block_on(system.request_job_cancellation(&claim, Timestamp::ZERO))
            .expect("cancellation commits"),
        CancellationResult::Requested
    );
    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::ZERO)),
        Err(JobSystemError::LeaseLost)
    ));
    let before = store.snapshot().expect("snapshot succeeds");
    assert_eq!(
        block_on(system.request_job_cancellation(&claim, Timestamp::ZERO))
            .expect("repeated cancellation succeeds"),
        CancellationResult::Requested
    );
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
    assert!(matches!(
        block_on(system.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_an_unclaimed_job_when_cancelling_then_no_live_route_can_claim_it() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::ZERO)).expect("cancel commits"),
        CancellationResult::Cancelled
    );
    assert!(matches!(
        block_on(system.claim(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(
        block_on(
            system.store().get(
                crate::keys::due_key(
                    system.namespace(),
                    &QueueName::try_new("default").expect("queue"),
                    Timestamp::ZERO,
                    &id,
                )
                .expect("due key")
            )
        )
        .expect("due read succeeds")
        .is_none()
    );
}

#[test]
fn given_a_leased_job_when_cancellation_is_requested_then_commit_releases_without_reversing_effects()
 {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    block_on(system.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    assert_eq!(
        block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1)))
            .expect("cancellation request commits"),
        CancellationResult::Requested
    );
    assert!(claim.cancellation().is_cancelled());
    assert_eq!(
        block_on(system.cancel_claim(claim, Timestamp::from_millis(1)))
            .expect("cancellation commit succeeds"),
        CancellationResult::Cancelled
    );
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key is valid")),
    )
    .expect("job read succeeds")
    .expect("cancelled job remains present");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Cancelled));
    assert!(matches!(
        block_on(system.claim(id, Timestamp::from_millis(2))),
        Err(JobSystemError::LeaseConflict)
    ));
}

#[test]
fn given_a_committed_cancellation_when_outcomes_race_then_the_marker_survives() {
    for (id_byte, outcome) in [
        (
            11_u8,
            JobOutcome::Retry {
                class: RetryClass::Transient,
                not_before: None,
                code: OutcomeCode::try_new("transient").expect("outcome is valid"),
            },
        ),
        (
            12_u8,
            JobOutcome::Continue {
                not_before: Timestamp::from_millis(2),
                checkpoint: bytes::Bytes::new(),
            },
        ),
        (
            13_u8,
            JobOutcome::Complete(OutcomeCode::try_new("completed").expect("outcome is valid")),
        ),
    ] {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([id_byte; 16]);
        block_on(system.enqueue_raw(low_volume_job(id_byte, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
        block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1)))
            .expect("cancellation request commits");

        let result = block_on(system.apply_outcome(claim, outcome, Timestamp::from_millis(1)));
        assert!(
            matches!(result, Err(JobSystemError::LeaseLost)),
            "a committed cancellation must defeat a racing outcome: {result:?}"
        );
        let cancellation_key = crate::keys::cancellation_key(system.namespace(), &id)
            .expect("cancellation key is valid");
        let cancellation = block_on(system.store().get(cancellation_key))
            .expect("cancellation read succeeds")
            .expect("cancellation marker remains");
        crate::keys::validate_empty_marker(&cancellation, crate::codec::ValueTag::Cancellation)
            .expect("cancellation marker remains canonical");
    }
}

#[test]
fn given_a_claim_when_job_authority_changes_before_cancellation_request_then_request_is_rejected() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([4; 16]);
    block_on(system.enqueue_raw(low_volume_job(4, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let cancellation = claim.cancellation();

    let mut successor = claim.record().clone();
    successor.revision += 1;
    store
        .put_raw(
            crate::keys::job_key(system.namespace(), &id).expect("job key is valid"),
            crate::codec::encode_job_record(&successor).expect("successor encodes"),
        )
        .expect("successor write succeeds");

    assert!(matches!(
        block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1))),
        Err(JobSystemError::LeaseLost)
    ));
    assert!(!cancellation.is_cancelled());
    assert!(
        !store
            .contains(
                &crate::keys::cancellation_key(system.namespace(), &id)
                    .expect("cancellation key is valid")
            )
            .expect("cancellation lookup succeeds")
    );
}

#[test]
fn given_a_scheduled_job_with_a_foreign_namespace_when_cancelling_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = low_volume_job(7, Timestamp::ZERO);
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");

    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(store.get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.namespace = Namespace::try_new(b"foreign").expect("foreign namespace is valid");
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(system.cancel_job(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not mutate the scheduled job or its routes"
    );
}

#[test]
fn given_a_scheduled_job_with_a_foreign_payload_chunk_when_cancelling_then_payload_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = low_volume_job(8, Timestamp::ZERO);
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");

    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(store.get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let foreign_id = JobId::from([0xee; 16]);
    record.payload.chunk_keys[0] =
        crate::keys::payload_key(system.namespace(), &foreign_id, 0).expect("payload key");
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(system.cancel_job(id, Timestamp::ZERO)),
        Err(JobSystemError::PayloadCorrupt)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "payload identity rejection must not mutate the scheduled job or its routes"
    );
}
