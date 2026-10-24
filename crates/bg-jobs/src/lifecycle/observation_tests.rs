use bytes::Bytes;

use crate::{
    codec::{ValueCodec, ValueTag},
    test_helper::{block_on, completion, low_volume_job, system},
    *,
};

#[test]
fn given_a_live_job_when_observed_then_record_and_operation_marker_are_returned() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    assert!(matches!(
        observation,
        LifecycleObservation::Current {
            operation_id: None,
            ..
        }
    ));

    let claim = block_on(engine.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    let operation = claim.operation_id();
    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    assert!(matches!(
        observation,
        LifecycleObservation::Current {
            operation_id: Some(value),
            ..
        } if value == operation
    ));
}

#[test]
fn given_a_live_job_when_observed_then_durable_routes_and_payload_state_are_returned() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([3; 16]);
    block_on(engine.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Current {
        record,
        routes,
        cancellation_requested,
        status,
        ..
    } = observation
    else {
        panic!("enqueued job must be current");
    };
    assert_eq!(status, LifecycleRecordStatus::Valid);
    assert_eq!(record.state, JobState::Scheduled);
    assert!(record.payload.complete);
    assert!(routes.due);
    assert!(routes.fair);
    assert!(routes.wake);
    assert!(!routes.lease);
    assert!(!cancellation_requested);

    let _claim = block_on(engine.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Current {
        record,
        routes,
        cancellation_requested,
        status,
        ..
    } = observation
    else {
        panic!("claimed job must be current");
    };
    assert_eq!(status, LifecycleRecordStatus::Valid);
    assert!(matches!(record.state, JobState::Leased(_)));
    assert!(record.payload.complete);
    assert!(!routes.due);
    assert!(!routes.fair);
    assert!(!routes.wake);
    assert!(routes.lease);
    assert!(!cancellation_requested);
}

#[test]
fn given_a_terminal_receipt_when_observed_then_bounded_receipt_is_returned() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([4; 16]);
    block_on(engine.enqueue_raw(low_volume_job(4, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::from_millis(10)))
        .expect("completion commits");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Terminal(receipt) = observation else {
        panic!("completion must leave a terminal receipt");
    };
    assert_eq!(receipt.job_id, job_id);
}

#[test]
fn given_an_unreadable_job_record_when_observed_then_its_status_is_preserved() {
    for (job_id, encoded, expected) in [
        (
            JobId::from([5; 16]),
            Bytes::from_static(&[0x7f]),
            LifecycleRecordStatus::UnknownVersion,
        ),
        (
            JobId::from([6; 16]),
            Bytes::from_static(&[0x01, 0x01]),
            LifecycleRecordStatus::Corrupt,
        ),
    ] {
        let store = FakeStore::new();
        let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
        block_on(engine.enqueue_raw(
            low_volume_job(job_id.as_bytes()[0], Timestamp::ZERO),
            Timestamp::ZERO,
        ))
        .expect("enqueue commits");
        let key = crate::keys::job_key(engine.namespace(), &job_id).expect("job key is valid");
        store.put_raw(key, encoded).expect("corrupt fixture writes");

        let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
        let LifecycleObservation::Invalid { status, routes, .. } = observation else {
            panic!("unreadable record must be observable");
        };
        assert_eq!(status, expected);
        assert!(!routes.due);
        assert!(!routes.fair);
        assert!(!routes.wake);
        assert!(!routes.lease);
    }
}

#[test]
fn given_missing_payload_or_route_state_when_observed_then_the_gap_is_visible() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([7; 16]);
    block_on(engine.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let payload_key =
        crate::keys::payload_key(engine.namespace(), &job_id, 0).expect("payload key is valid");
    let due_key = crate::keys::due_key(
        engine.namespace(),
        &QueueName::try_new("default").expect("queue is valid"),
        Timestamp::ZERO,
        &job_id,
    )
    .expect("due key is valid");
    let cancellation_key = crate::keys::cancellation_key(engine.namespace(), &job_id)
        .expect("cancellation key is valid");
    store
        .delete_raw(&payload_key)
        .expect("payload fixture deletes");
    store.delete_raw(&due_key).expect("due fixture deletes");
    store
        .put_raw(
            cancellation_key,
            crate::keys::cancellation_value().expect("cancellation value encodes"),
        )
        .expect("cancellation fixture writes");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Current {
        record,
        routes,
        cancellation_requested,
        ..
    } = observation
    else {
        panic!("live job must remain observable");
    };
    assert!(!record.payload.complete);
    assert!(!routes.due);
    assert!(routes.fair);
    assert!(routes.wake);
    assert!(!routes.lease);
    assert!(cancellation_requested);
}

#[test]
fn given_an_unknown_operation_value_when_observed_then_unknown_version_is_reported() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([8; 16]);
    block_on(engine.enqueue_raw(low_volume_job(8, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let operation_key =
        crate::keys::operation_key(engine.namespace(), &job_id).expect("operation key is valid");
    store
        .put_raw(operation_key, Bytes::from_static(&[0x7f]))
        .expect("unknown operation fixture writes");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Invalid { status, routes, .. } = observation else {
        panic!("unknown operation must be observable");
    };
    assert_eq!(status, LifecycleRecordStatus::UnknownVersion);
    assert!(routes.due);
    assert!(routes.fair);
    assert!(routes.wake);
    assert!(!routes.lease);
}

#[test]
fn given_successful_completion_when_observed_then_exact_terminal_receipt_is_returned() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([2; 16]);
    block_on(engine.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    let operation = claim.operation_id();
    let generation = claim.record().generation;
    let revision = claim.record().revision + 1;
    let completed_at = Timestamp::from_millis(10);

    block_on(engine.complete(claim, completion(), completed_at)).expect("completion commits");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Terminal(receipt) = observation else {
        panic!("completion must leave a terminal receipt");
    };
    assert_eq!(receipt.operation_id, operation);
    assert_eq!(receipt.job_id, job_id);
    assert_eq!(receipt.generation, generation);
    assert_eq!(receipt.revision, revision);
    assert_eq!(receipt.completed_at, completed_at);
    assert_eq!(receipt.terminal, TerminalDisposition::Completed);
    assert_eq!(
        block_on(engine.reconcile(job_id, operation)).expect("reconcile succeeds"),
        ReconciliationOutcome::AlreadyCommitted
    );
}

#[test]
fn given_a_wrong_tagged_payload_chunk_when_observed_then_payload_is_incomplete() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 9);
    let job_id = JobId::from([9; 16]);
    block_on(engine.enqueue_raw(low_volume_job(9, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let payload_key =
        crate::keys::payload_key(engine.namespace(), &job_id, 0).expect("payload key is valid");
    store
        .put_raw(
            payload_key,
            ValueCodec::encode(ValueTag::Due, b"payload").expect("wrong-tagged payload encodes"),
        )
        .expect("wrong-tagged payload fixture writes");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Current { record, status, .. } = observation else {
        panic!("wrong-tagged payload must remain observable");
    };
    assert_eq!(status, LifecycleRecordStatus::Valid);
    assert!(!record.payload.complete);
}

#[test]
fn given_a_digest_mismatched_payload_chunk_when_observed_then_payload_is_incomplete() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 10);
    let job_id = JobId::from([10; 16]);
    block_on(engine.enqueue_raw(low_volume_job(10, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let payload_key =
        crate::keys::payload_key(engine.namespace(), &job_id, 0).expect("payload key is valid");
    store
        .put_raw(
            payload_key,
            ValueCodec::encode(ValueTag::PayloadChunk, b"changed")
                .expect("digest-mismatched payload encodes"),
        )
        .expect("digest-mismatched payload fixture writes");

    let observation = block_on(engine.observe_lifecycle(job_id)).expect("observation succeeds");
    let LifecycleObservation::Current { record, status, .. } = observation else {
        panic!("digest-mismatched payload must remain observable");
    };
    assert_eq!(status, LifecycleRecordStatus::Valid);
    assert!(!record.payload.complete);
}
