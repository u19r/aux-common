use crate::{
    test_helper::{block_on, job, low_volume_job, system},
    *,
};

#[test]
fn given_a_cancelled_worker_disappears_when_its_lease_expires_then_cancellation_is_finalized() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([14; 16]);
    block_on(system.enqueue_raw(low_volume_job(14, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(system.cancel_job(id, Timestamp::from_millis(1)))
        .expect("cancellation request commits");
    drop(claim);
    assert_eq!(
        block_on(system.expire_job(id, Timestamp::from_millis(999))).expect("lease remains live"),
        ExpiryResult::Unchanged
    );
    assert!(matches!(
        block_on(system.expire_job(id, Timestamp::from_millis(1_001))),
        Ok(ExpiryResult::Cancelled)
    ));
    let cancellation_key =
        crate::keys::cancellation_key(system.namespace(), &id).expect("cancellation key is valid");
    assert!(
        block_on(system.store().get(cancellation_key))
            .expect("read succeeds")
            .is_none()
    );
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key")),
    )
    .expect("read succeeds")
    .expect("terminal record exists");
    assert!(matches!(
        crate::codec::decode_job_record(&encoded)
            .expect("record")
            .state,
        JobState::Cancelled
    ));
    assert!(matches!(
        block_on(system.claim(id, Timestamp::from_millis(1_001))),
        Err(JobSystemError::LeaseConflict)
    ));
}

#[test]
fn given_a_committed_cancellation_when_the_lease_expires_then_reclaim_cannot_reissue_it() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([15; 16]);
    block_on(system.enqueue_raw(low_volume_job(15, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1)))
        .expect("cancellation request commits");

    assert!(matches!(
        block_on(system.claim(id, Timestamp::from_millis(1_001))),
        Err(JobSystemError::LeaseConflict)
    ));
    let cancellation_key =
        crate::keys::cancellation_key(system.namespace(), &id).expect("cancellation key is valid");
    let cancellation = block_on(system.store().get(cancellation_key))
        .expect("cancellation read succeeds")
        .expect("cancellation marker remains");
    crate::keys::validate_empty_marker(&cancellation, crate::codec::ValueTag::Cancellation)
        .expect("cancellation marker remains canonical");
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key is valid")),
    )
    .expect("job read succeeds")
    .expect("job remains present");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Leased(_)));
}

#[test]
fn given_a_scheduled_job_with_a_foreign_namespace_when_expiring_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = job(
        7,
        bytes::Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        Some(Timestamp::from_millis(1)),
        None,
    );
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
        block_on(system.expire_job(id, Timestamp::from_millis(2))),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not mutate the expired job or its routes"
    );
}

#[test]
fn given_a_scheduled_job_with_a_foreign_payload_chunk_when_expiring_then_payload_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = job(
        8,
        bytes::Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        Some(Timestamp::from_millis(1)),
        None,
    );
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
        block_on(system.expire_job(id, Timestamp::from_millis(2))),
        Err(JobSystemError::PayloadCorrupt)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "payload identity rejection must not mutate the expired job or its routes"
    );
}

#[test]
fn given_a_scheduled_job_with_a_tampered_due_marker_when_expiring_then_route_is_rejected_before_mutation()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = job(
        9,
        bytes::Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        Some(Timestamp::from_millis(1)),
        None,
    );
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");

    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(store.get(job_key))
        .expect("job read succeeds")
        .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let due_key = crate::keys::due_key(system.namespace(), &record.queue, record.scheduled_at, &id)
        .expect("due key is valid");
    store
        .put_raw(
            due_key,
            crate::keys::due_value(Timestamp::from_millis(99)).expect("due marker encodes"),
        )
        .expect("tampered due marker write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(system.expire_job(id, Timestamp::from_millis(2))),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "route validation must happen before expiry mutations are prepared"
    );
}

#[test]
fn given_an_expired_lease_when_reclaiming_then_retry_state_and_routes_are_published_atomically() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    block_on(system.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.expire_job(id, Timestamp::from_millis(1_000)))
        .expect("expiry transition commits");
    assert_eq!(result, ExpiryResult::LeaseExpired);
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    assert!(matches!(
        crate::codec::decode_job_record(&encoded)
            .expect("record decodes")
            .state,
        JobState::Scheduled
    ));
    assert!(block_on(system.claim(id, Timestamp::from_millis(1_000))).is_ok());
    drop(claim);
}

#[test]
fn given_a_cancelled_expired_worker_when_commit_acknowledgement_is_lost_then_recovery_releases_its_permits()
 {
    for (index, applied) in [(16, false), (17, true)] {
        let store = FakeStore::local();
        let system = system(
            store.clone(),
            FairnessPolicy::from(std::num::NonZeroU16::MIN),
            1,
        );
        let job = job(
            index,
            bytes::Bytes::from_static(b"payload"),
            crate::test_helper::scoped_fairness(),
            Timestamp::ZERO,
            Some(Timestamp::from_millis(500)),
            None,
        );
        let id = job.job_id;
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue");
        let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
        let permits = claim.permit_keys().to_vec();
        assert!(!permits.is_empty());
        block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel");
        drop(claim);
        if applied {
            store.queue_unknown_after_commit().expect("queue fault");
        } else {
            store.queue_unknown_before_commit().expect("queue fault");
        }
        assert_eq!(
            block_on(system.expire_job(id, Timestamp::from_millis(1000))).expect("recovery"),
            ExpiryResult::Cancelled
        );
        for permit in permits {
            assert!(block_on(store.get(permit)).expect("permit read").is_none());
        }
        let record = crate::codec::decode_job_record(
            &block_on(store.get(crate::keys::job_key(system.namespace(), &id).expect("key")))
                .expect("read")
                .expect("record"),
        )
        .expect("decode");
        assert!(
            matches!(record.state, JobState::Cancelled),
            "cancellation takes precedence over age exhaustion"
        );
        assert_eq!(
            block_on(system.expire_job(id, Timestamp::from_millis(1001))).expect("repeat recovery"),
            ExpiryResult::Unchanged
        );
    }
}

#[test]
fn given_a_malformed_cancellation_marker_when_expiring_a_lease_then_no_state_is_mutated() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([18; 16]);
    block_on(system.enqueue_raw(low_volume_job(18, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue");
    block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
    store
        .put_raw(
            crate::keys::cancellation_key(system.namespace(), &id).expect("key"),
            bytes::Bytes::from_static(b"malformed"),
        )
        .expect("tamper marker");
    let before = store.snapshot().expect("snapshot");
    assert!(matches!(
        block_on(system.expire_job(id, Timestamp::from_millis(1000))),
        Err(JobSystemError::PayloadCorrupt)
    ));
    assert_eq!(store.snapshot().expect("snapshot"), before);
}

#[test]
fn given_a_cancellation_recovery_conflict_when_expiring_a_lease_then_the_marker_and_authority_survive()
 {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([19; 16]);
    block_on(system.enqueue_raw(low_volume_job(19, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue");
    block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
    block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel");
    let before = store.snapshot().expect("snapshot");
    store
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("queue conflict");
    assert!(matches!(
        block_on(system.expire_job(id, Timestamp::from_millis(1000))),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot"), before);
}

#[test]
fn given_a_job_age_exhausted_during_a_lease_when_expiring_then_the_dead_letter_reason_is_expiry() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job = job(
        20,
        bytes::Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        Some(Timestamp::from_millis(500)),
        None,
    );
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue");
    block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
    assert_eq!(
        block_on(system.expire_job(id, Timestamp::from_millis(1000))).expect("expiry"),
        ExpiryResult::DeadLettered
    );
    let encoded = block_on(store.get(crate::keys::job_key(system.namespace(), &id).expect("key")))
        .expect("read")
        .expect("record");
    let record = crate::codec::decode_job_record(&encoded).expect("record");
    assert!(matches!(record.state, JobState::DeadLettered));
    assert_eq!(
        record
            .attempts
            .expect("attempt exists")
            .last_outcome
            .expect("outcome exists")
            .as_str(),
        "expired"
    );
}
