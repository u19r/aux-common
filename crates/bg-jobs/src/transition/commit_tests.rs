use crate::{
    JobOutcome, JobSystem,
    error::JobSystemError,
    failure::{CancellationResult, OutcomeResult},
    ids::JobId,
    lifecycle::ClaimedJob,
    policy::{FairnessPolicy, OutcomeCode},
    store::JobStore,
    test_helper::{FakeStore, block_on, completion, low_volume_job, system},
    time::Timestamp,
};

fn claim_job(system: &JobSystem<FakeStore>, id: u8) -> ClaimedJob {
    let job_id = JobId::from([id; 16]);
    block_on(system.enqueue_raw(low_volume_job(id, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    block_on(system.claim(job_id, Timestamp::ZERO)).expect("claim commits")
}

#[test]
fn given_completion_unknown_before_commit_when_reconciling_then_no_handler_repeat_is_needed() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let claim = claim_job(&system, 1);
    let operation = claim.operation_id();
    store
        .queue_unknown_before_commit()
        .expect("unknown-before queued");
    store
        .queue_unknown_before_commit()
        .expect("retry unknown-before queued");
    store
        .queue_unknown_before_commit()
        .expect("ambiguous pending admission queues");

    assert!(matches!(
        block_on(system.complete(claim, completion(), Timestamp::from_millis(1))),
        Err(JobSystemError::UnknownCommit)
    ));
    assert!(
        matches!(block_on(system.observe_lifecycle(JobId::from([1; 16]))).unwrap(),
        crate::LifecycleObservation::Current { operation_id: Some(current), .. } if current == operation)
    );
}

#[test]
fn given_completion_unknown_after_commit_when_reconciling_then_terminal_deletion_is_observed() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    let claim = claim_job(&system, 2);
    store
        .queue_unknown_after_commit()
        .expect("unknown-after queued");

    assert!(block_on(system.complete(claim, completion(), Timestamp::from_millis(1))).is_ok());
    assert!(
        block_on(
            system
                .store()
                .get(crate::keys::job_key(system.namespace(), &id).expect("job key"))
        )
        .expect("job read succeeds")
        .is_none()
    );
}

#[test]
fn given_dead_letter_unknown_results_before_or_after_commit_then_the_record_is_not_replayed() {
    for (id_byte, after) in [(3_u8, false), (4_u8, true)] {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let claim = claim_job(&system, id_byte);
        if after {
            store
                .queue_unknown_after_commit()
                .expect("unknown-after queued");
        } else {
            store
                .queue_unknown_before_commit()
                .expect("unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("retry unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("ambiguous pending admission queues");
        }
        let result = block_on(system.apply_outcome(
            claim,
            JobOutcome::DeadLetter {
                code: OutcomeCode::try_new("permanent").expect("code is valid"),
            },
            Timestamp::from_millis(1),
        ));
        if after {
            assert!(matches!(result, Ok(OutcomeResult::DeadLettered { .. })));
        } else {
            assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
        }
    }
}

#[test]
fn given_scheduled_cancellation_unknown_results_then_reconciliation_sees_the_terminal_state() {
    for (id_byte, after) in [(5_u8, false), (6_u8, true)] {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([id_byte; 16]);
        block_on(system.enqueue_raw(low_volume_job(id_byte, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        if after {
            store
                .queue_unknown_after_commit()
                .expect("unknown-after queued");
        } else {
            store
                .queue_unknown_before_commit()
                .expect("unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("retry unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("ambiguous pending admission queues");
        }
        let result = block_on(system.cancel_job(id, Timestamp::ZERO));
        if after {
            assert!(matches!(result, Ok(CancellationResult::Cancelled)));
        } else {
            assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
        }
    }
}

#[test]
fn given_leased_cancellation_unknown_before_or_after_commit_then_the_claim_is_not_replayed() {
    for (id_byte, after) in [(7_u8, false), (8_u8, true)] {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let claim = claim_job(&system, id_byte);
        let operation = claim.operation_id();
        if after {
            store
                .queue_unknown_after_commit()
                .expect("unknown-after queued");
        } else {
            store
                .queue_unknown_before_commit()
                .expect("unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("retry unknown-before queued");
            store
                .queue_unknown_before_commit()
                .expect("ambiguous pending admission queues");
        }
        let result =
            block_on(system.apply_outcome(claim, JobOutcome::Cancelled, Timestamp::from_millis(1)));
        if after {
            assert!(matches!(result, Ok(OutcomeResult::Cancelled)));
        } else {
            assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
        }
        let observation = block_on(system.observe_lifecycle(JobId::from([id_byte; 16]))).unwrap();
        assert!(
            matches!(observation, crate::LifecycleObservation::Current { operation_id: Some(current), .. }
            if (current == operation) == !after)
        );
    }
}

#[test]
fn given_a_malformed_wake_key_when_a_command_conflicts_then_recovery_rejects_it_without_changing_the_value()
 {
    let store = FakeStore::distributed();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let prefix =
        crate::codec::KeyCodec::encode(system.namespace(), crate::codec::KeyTag::Wake, &[])
            .unwrap();
    let mut malformed = prefix.as_bytes().to_vec();
    malformed.push(0);
    let key = crate::store::StoreKey::try_from(malformed).unwrap();
    let existing = crate::keys::wake_value(Timestamp::from_millis(1)).unwrap();
    store.put_raw(key.clone(), existing.clone()).unwrap();
    let input = crate::transition::checked_transaction(
        &system,
        vec![crate::store::Check::Absent(key.clone())],
        vec![crate::store::Mutation::Put(
            key.clone(),
            crate::keys::wake_value(Timestamp::ZERO).unwrap(),
        )],
    )
    .unwrap();
    assert!(matches!(
        block_on(system.commit_durable(input)),
        Err(JobSystemError::StoreData(_))
    ));
    assert_eq!(block_on(store.get(key)).unwrap(), Some(existing));
}
