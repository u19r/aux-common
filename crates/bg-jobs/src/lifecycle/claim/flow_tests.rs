use std::num::NonZeroU64;

use bytes::Bytes;

use crate::{
    codec::encode_job_record,
    test_helper::{block_on, job, low_volume_job, system},
    *,
};

fn write_record(store: &FakeStore, engine: &JobSystem<FakeStore>, id: JobId, record: &JobRecordV1) {
    store
        .put_raw(
            crate::keys::job_key(engine.namespace(), &id).expect("job key is valid"),
            encode_job_record(record).expect("record encodes"),
        )
        .expect("record write succeeds");
    store
        .put_raw(
            crate::keys::lease_key(engine.namespace(), &record.queue, &id)
                .expect("lease key is valid"),
            crate::keys::lease_value(&id).expect("lease value is valid"),
        )
        .expect("lease route succeeds");
}

fn expired_record(encoded: &[u8]) -> JobRecordV1 {
    let mut record = crate::codec::decode_job_record(encoded).expect("record decodes");
    record.state = JobState::Leased(
        Lease::try_new(
            OwnerId::from([1; 16]),
            LeaseToken::from([3; 16]),
            NonZeroU64::new(1).expect("fence is non-zero"),
            Timestamp::from_millis(1),
        )
        .expect("lease is valid"),
    );
    record.revision = 1;
    record
}

fn restore_due(store: &FakeStore, engine: &JobSystem<FakeStore>, id: JobId) {
    store
        .put_raw(
            crate::keys::due_key(
                engine.namespace(),
                &QueueName::try_new("default").expect("queue is valid"),
                Timestamp::ZERO,
                &id,
            )
            .expect("due key is valid"),
            crate::keys::due_value(Timestamp::ZERO).expect("due value is valid"),
        )
        .expect("due route replacement succeeds");
}

#[test]
fn given_a_future_due_record_when_claiming_before_schedule_then_stale_discovery_is_rejected() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let record = job(
        1,
        Bytes::new(),
        FairnessClass::low_volume(),
        Timestamp::from_millis(50),
        None,
        None,
    );
    block_on(engine.enqueue_raw(record, Timestamp::ZERO)).expect("enqueue commits");

    assert!(matches!(
        block_on(engine.claim(JobId::from([1; 16]), Timestamp::from_millis(49))),
        Err(JobSystemError::LeaseConflict)
    ));
}

#[test]
fn given_a_due_index_record_mismatch_when_driving_then_the_stale_candidate_is_not_claimed() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let job_key = crate::keys::job_key(engine.namespace(), &id).expect("job key is valid");
    let encoded = block_on(engine.store().get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.scheduled_at = Timestamp::from_millis(1);
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");

    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: crate::test_helper::one(1),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024)
            .expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: crate::test_helper::one(64),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid");
    let report = block_on(engine.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("drive reports");

    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.counts.succeeded, 0);
    assert_eq!(report.stop_reason, DriveStopReason::NoVisibleWork);
    assert!(
        block_on(
            engine.store().get(
                crate::keys::due_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    Timestamp::ZERO,
                    &id,
                )
                .expect("due key is valid"),
            )
        )
        .expect("due read succeeds")
        .is_some()
    );
}

#[test]
fn given_a_tampered_due_value_when_claiming_directly_then_snapshot_is_unchanged() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let due_key = crate::keys::due_key(
        engine.namespace(),
        &QueueName::try_new("default").expect("queue is valid"),
        Timestamp::ZERO,
        &id,
    )
    .expect("due key is valid");
    store
        .put_raw(
            due_key,
            crate::keys::due_value(Timestamp::from_millis(1)).expect("tampered due value encodes"),
        )
        .expect("tampered due value writes");
    let before = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(engine.claim(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_two_nodes_when_claiming_one_due_job_then_exactly_one_claim_commits() {
    let store = FakeStore::distributed();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let second = system(store.clone(), FairnessPolicy::low_volume(), 2);
    block_on(first.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let first_claim = block_on(first.claim(JobId::from([1; 16]), Timestamp::ZERO));
    let second_claim = block_on(second.claim(JobId::from([1; 16]), Timestamp::ZERO));

    assert!(first_claim.is_ok());
    assert!(matches!(second_claim, Err(JobSystemError::LeaseConflict)));
}

#[test]
fn given_an_expired_lease_discovered_again_when_claiming_then_the_fence_increments() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let encoded = block_on(
        engine
            .store()
            .get(crate::keys::job_key(engine.namespace(), &id).expect("job key is valid")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    let record = expired_record(&encoded);
    write_record(&store, &engine, id, &record);
    restore_due(&store, &engine, id);

    let claimed =
        block_on(engine.claim(id, Timestamp::from_millis(2))).expect("expired lease reclaims");
    let lease = match &claimed.record().state {
        JobState::Leased(lease) => lease,
        _ => panic!("reclaimed job must be leased"),
    };
    assert_eq!(lease.owner, OwnerId::from([2; 16]));
    assert_eq!(lease.fence, NonZeroU64::new(2).expect("fence is non-zero"));
    assert_eq!(lease.expires_at, Timestamp::from_millis(1_002));
}

#[test]
fn given_a_claim_commit_conflict_when_claiming_then_no_lease_or_route_is_partially_written() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    store
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("queue conflict outcome");

    assert!(matches!(
        block_on(engine.claim(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(
        block_on(
            engine.store().get(
                crate::keys::lease_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &id,
                )
                .expect("lease key is valid"),
            )
        )
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(
            engine.store().get(
                crate::keys::due_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    Timestamp::ZERO,
                    &id,
                )
                .expect("due key is valid")
            )
        )
        .expect("due read succeeds")
        .is_some()
    );
}

#[test]
fn given_a_maxed_fence_high_water_when_claiming_then_overflow_is_rejected_without_mutation() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([11; 16]);
    block_on(engine.enqueue_raw(low_volume_job(11, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let operation_key =
        crate::keys::operation_key(engine.namespace(), &id).expect("operation key is valid");
    store
        .put_raw(
            operation_key.clone(),
            crate::keys::operation_value(&id, &OperationId::from([0xaa; 16]), u64::MAX)
                .expect("maxed operation marker encodes"),
        )
        .expect("maxed operation marker writes");
    let before = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(engine.claim(id, Timestamp::ZERO)),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
    assert!(
        block_on(engine.store().get(operation_key))
            .expect("operation read succeeds")
            .is_some()
    );
}

#[test]
fn given_a_persisted_record_with_a_foreign_namespace_when_claiming_then_identity_is_rejected_before_transition()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let requested_id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let job_key =
        crate::keys::job_key(engine.namespace(), &requested_id).expect("job key is valid");
    let encoded = block_on(engine.store().get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.namespace = Namespace::try_new(b"foreign").expect("foreign namespace is valid");
    let tampered = encode_job_record(&record).expect("tampered record encodes");
    store
        .put_raw(job_key.clone(), tampered.clone())
        .expect("tampered record write succeeds");
    let due_key = crate::keys::due_key(
        engine.namespace(),
        &record.queue,
        record.scheduled_at,
        &requested_id,
    )
    .expect("due key is valid");

    let result = block_on(engine.claim(requested_id, Timestamp::ZERO));

    assert!(
        result.is_err(),
        "foreign persisted namespace must not claim"
    );
    assert_eq!(
        block_on(engine.store().get(job_key))
            .expect("job read succeeds")
            .as_deref(),
        Some(tampered.as_ref())
    );
    assert!(
        block_on(
            engine.store().get(
                crate::keys::lease_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &requested_id,
                )
                .expect("lease key is valid")
            )
        )
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(engine.store().get(due_key))
            .expect("due read succeeds")
            .is_some()
    );
}

#[test]
fn given_a_persisted_record_with_a_foreign_job_id_when_claiming_then_identity_is_rejected_before_transition()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let requested_id = JobId::from([1; 16]);
    let persisted_id = JobId::from([2; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let requested_key =
        crate::keys::job_key(engine.namespace(), &requested_id).expect("requested key is valid");
    let encoded = block_on(engine.store().get(requested_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.job_id = persisted_id;
    let tampered = encode_job_record(&record).expect("tampered record encodes");
    store
        .put_raw(requested_key.clone(), tampered.clone())
        .expect("requested tampered record write succeeds");
    store
        .put_raw(
            crate::keys::job_key(engine.namespace(), &persisted_id)
                .expect("persisted key is valid"),
            tampered.clone(),
        )
        .expect("persisted tampered record write succeeds");
    let due_key = crate::keys::due_key(
        engine.namespace(),
        &record.queue,
        record.scheduled_at,
        &requested_id,
    )
    .expect("due key is valid");

    let result = block_on(engine.claim(requested_id, Timestamp::ZERO));

    assert!(result.is_err(), "foreign persisted job ID must not claim");
    assert_eq!(
        block_on(engine.store().get(requested_key))
            .expect("requested record read succeeds")
            .as_deref(),
        Some(tampered.as_ref())
    );
    assert_eq!(
        block_on(
            engine.store().get(
                crate::keys::job_key(engine.namespace(), &persisted_id)
                    .expect("persisted key is valid")
            )
        )
        .expect("persisted record read succeeds")
        .as_deref(),
        Some(tampered.as_ref())
    );
    assert!(
        block_on(
            engine.store().get(
                crate::keys::lease_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &persisted_id,
                )
                .expect("lease key is valid")
            )
        )
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(engine.store().get(due_key))
            .expect("due read succeeds")
            .is_some()
    );
}

#[test]
fn given_a_persisted_manifest_with_a_foreign_chunk_key_when_claiming_then_redirected_payload_is_rejected_before_transition()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let requested_id = JobId::from([1; 16]);
    let foreign_namespace = Namespace::try_new(b"foreign").expect("foreign namespace is valid");
    let foreign_id = JobId::from([3; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let requested_key =
        crate::keys::job_key(engine.namespace(), &requested_id).expect("requested key is valid");
    let encoded = block_on(engine.store().get(requested_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let canonical_chunk = record.payload.chunk_keys[0].clone();
    let chunk = block_on(engine.store().get(canonical_chunk))
        .expect("canonical chunk read succeeds")
        .expect("canonical chunk exists");
    let foreign_chunk = crate::keys::payload_key(&foreign_namespace, &foreign_id, 0)
        .expect("foreign chunk key is valid");
    store
        .put_raw(foreign_chunk.clone(), chunk)
        .expect("foreign chunk write succeeds");
    record.payload.chunk_keys = vec![foreign_chunk];
    let tampered = encode_job_record(&record).expect("tampered record encodes");
    store
        .put_raw(requested_key.clone(), tampered.clone())
        .expect("tampered record write succeeds");
    let due_key = crate::keys::due_key(
        engine.namespace(),
        &record.queue,
        record.scheduled_at,
        &requested_id,
    )
    .expect("due key is valid");

    let result = block_on(engine.claim(requested_id, Timestamp::ZERO));

    assert!(
        result.is_err(),
        "foreign payload key must not redirect reads"
    );
    assert_eq!(
        block_on(engine.store().get(requested_key))
            .expect("record read succeeds")
            .as_deref(),
        Some(tampered.as_ref())
    );
    assert!(
        block_on(
            engine.store().get(
                crate::keys::lease_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &requested_id,
                )
                .expect("lease key is valid")
            )
        )
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(engine.store().get(due_key))
            .expect("due read succeeds")
            .is_some()
    );
}

#[test]
fn given_a_persisted_manifest_with_another_jobs_chunk_key_when_claiming_then_rebinding_is_rejected_before_transition()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let requested_id = JobId::from([1; 16]);
    let other_id = JobId::from([3; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let requested_key =
        crate::keys::job_key(engine.namespace(), &requested_id).expect("requested key is valid");
    let encoded = block_on(engine.store().get(requested_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let canonical_chunk = record.payload.chunk_keys[0].clone();
    let chunk = block_on(engine.store().get(canonical_chunk))
        .expect("canonical chunk read succeeds")
        .expect("canonical chunk exists");
    let other_chunk =
        crate::keys::payload_key(engine.namespace(), &other_id, 0).expect("chunk key is valid");
    store
        .put_raw(other_chunk.clone(), chunk)
        .expect("other job chunk write succeeds");
    record.payload.chunk_keys = vec![other_chunk];
    let tampered = encode_job_record(&record).expect("tampered record encodes");
    store
        .put_raw(requested_key.clone(), tampered.clone())
        .expect("tampered record write succeeds");
    let due_key = crate::keys::due_key(
        engine.namespace(),
        &record.queue,
        record.scheduled_at,
        &requested_id,
    )
    .expect("due key is valid");

    let result = block_on(engine.claim(requested_id, Timestamp::ZERO));

    assert!(
        result.is_err(),
        "payload must not rebind to another job in the active namespace"
    );
    assert_eq!(
        block_on(engine.store().get(requested_key))
            .expect("record read succeeds")
            .as_deref(),
        Some(tampered.as_ref())
    );
    assert!(
        block_on(
            engine.store().get(
                crate::keys::lease_key(
                    engine.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &requested_id,
                )
                .expect("lease key is valid")
            )
        )
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(engine.store().get(due_key))
            .expect("due read succeeds")
            .is_some()
    );
}
