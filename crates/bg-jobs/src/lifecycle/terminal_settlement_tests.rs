use bytes::Bytes;

use crate::{
    FairnessPolicy, FakeStore, JobId, JobOutcome, JobSystemError, OutcomeCode, Timestamp,
    test_helper::{block_on, low_volume_job, system},
};

#[test]
fn given_reconciled_terminal_jobs_when_settled_then_payload_and_lifecycle_records_are_removed() {
    for outcome in [
        JobOutcome::Cancelled,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("failed").unwrap(),
        },
    ] {
        let store = FakeStore::distributed();
        let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let mut job = low_volume_job(1, Timestamp::ZERO);
        job.payload = Bytes::from(vec![42; 40_000]);
        block_on(engine.enqueue_raw(job, Timestamp::ZERO)).unwrap();
        let claim = block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
        block_on(engine.apply_outcome(claim, outcome, Timestamp::ZERO)).unwrap();
        let authority = block_on(engine.terminal_authority(JobId::from([1; 16])))
            .unwrap()
            .unwrap();
        block_on(engine.settle_terminal(authority)).unwrap();
        assert!(
            block_on(engine.terminal_authority(JobId::from([1; 16])))
                .unwrap()
                .is_none()
        );
        for tag in [
            crate::codec::KeyTag::Job,
            crate::codec::KeyTag::Operation,
            crate::codec::KeyTag::PayloadChunk,
            crate::codec::KeyTag::DeadLetter,
            crate::codec::KeyTag::FairReady,
            crate::codec::KeyTag::Lease,
            crate::codec::KeyTag::Cancellation,
            crate::codec::KeyTag::Due,
        ] {
            let prefix = crate::codec::KeyCodec::encode(engine.namespace(), tag, &[]).unwrap();
            assert!(
                !store
                    .snapshot()
                    .unwrap()
                    .iter()
                    .any(|(key, _)| key.as_bytes().starts_with(prefix.as_bytes())),
                "terminal-owned records remain: {tag:?}"
            );
        }
    }
}

#[test]
fn given_settled_snapshot_when_old_authority_is_reused_then_it_cannot_delete_new_work() {
    let store = FakeStore::distributed();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    block_on(engine.apply_outcome(claim, JobOutcome::Cancelled, Timestamp::ZERO)).unwrap();
    let authority = block_on(engine.terminal_authority(JobId::from([1; 16])))
        .unwrap()
        .unwrap();
    block_on(engine.settle_terminal(authority.clone())).unwrap();
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    assert!(matches!(
        block_on(engine.settle_terminal(authority)),
        Err(JobSystemError::LeaseLost)
    ));
    block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
}

#[test]
fn given_redriven_job_when_stale_terminal_settlement_arrives_then_live_payload_and_routes_survive()
{
    let store = FakeStore::distributed();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).unwrap();
    block_on(engine.apply_outcome(
        claim,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("failed").unwrap(),
        },
        Timestamp::ZERO,
    ))
    .unwrap();
    let authority = block_on(engine.terminal_authority(id)).unwrap().unwrap();
    let crate::LifecycleObservation::Current {
        record,
        operation_id: Some(operation),
        ..
    } = block_on(engine.observe_lifecycle(id)).unwrap()
    else {
        panic!("terminal record");
    };
    block_on(engine.redrive_job(
        id,
        crate::failure::RedriveRequest::new(
            record.revision,
            operation,
            crate::failure::RedriveExecution::ReuseExecutionId,
            Timestamp::ZERO,
        ),
    ))
    .unwrap();
    let before = crate::test_helper::application_snapshot(&store);
    assert!(matches!(
        block_on(engine.settle_terminal(authority)),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(crate::test_helper::application_snapshot(&store), before);
    block_on(engine.claim(id, Timestamp::ZERO)).unwrap();
}
