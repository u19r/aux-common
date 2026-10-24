use std::future::Future;

use crate::{
    test_helper::{block_on, low_volume_job, system},
    *,
};

fn terminal_acknowledgement_signature<S: JobStore>(
    system: &JobSystem<S>,
    claim: ClaimedJob,
    now: Timestamp,
) -> impl Future<Output = JobResult<CancellationResult, S::Error>> {
    system.cancel_claim(claim, now)
}

#[test]
fn given_shutdown_or_explicit_cancellation_when_a_handler_stops_then_only_shutdown_preserves_work()
{
    for (is_shutdown, is_requested) in [(true, false), (true, true), (false, true), (false, false)]
    {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([71; 16]);
        block_on(system.ensure_seed_raw(low_volume_job(71, Timestamp::ZERO), Timestamp::ZERO))
            .unwrap();
        let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
        block_on(system.apply_outcome(
            claim,
            JobOutcome::Continue {
                not_before: Timestamp::from_millis(1),
                checkpoint: bytes::Bytes::from_static(b"saved-cursor"),
            },
            Timestamp::ZERO,
        ))
        .unwrap();
        let claim = block_on(system.claim(id, Timestamp::from_millis(1))).unwrap();
        if is_requested {
            block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1))).unwrap();
        }
        if is_shutdown {
            system.request_shutdown();
        }
        let outcome =
            block_on(system.apply_outcome(claim, JobOutcome::Cancelled, Timestamp::from_millis(1)))
                .unwrap();
        let restarted = crate::test_helper::system(store, FairnessPolicy::low_volume(), 1);
        if is_shutdown && !is_requested {
            assert!(
                matches!(outcome, OutcomeResult::Continued { .. }),
                "service shutdown must preserve scheduled work"
            );
            let recovered = block_on(restarted.claim(id, Timestamp::from_millis(2))).unwrap();
            assert_eq!(
                recovered.record().checkpoint.as_deref(),
                Some(b"saved-cursor".as_slice())
            );
        } else {
            assert_eq!(outcome, OutcomeResult::Cancelled);
            assert!(matches!(
                block_on(restarted.claim(id, Timestamp::from_millis(2))),
                Err(JobSystemError::LeaseConflict)
            ));
        }
    }
}

#[test]
fn given_a_leased_job_without_a_cancellation_request_when_acknowledging_then_it_is_rejected() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([5; 16]);
    block_on(system.enqueue_raw(low_volume_job(5, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let cancellation = claim.cancellation();

    assert!(matches!(
        block_on(system.cancel_claim(claim, Timestamp::from_millis(1))),
        Err(JobSystemError::LeaseConflict)
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
fn given_a_cancelled_claim_when_acknowledging_again_then_terminal_authority_is_rejected() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([6; 16]);
    block_on(system.enqueue_raw(low_volume_job(6, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    assert_eq!(
        block_on(system.request_job_cancellation(&claim, Timestamp::from_millis(1)))
            .expect("cancellation request commits"),
        CancellationResult::Requested
    );
    assert_eq!(
        block_on(system.cancel_claim(claim, Timestamp::from_millis(1)))
            .expect("cancellation acknowledgement commits"),
        CancellationResult::Cancelled
    );

    assert!(matches!(
        block_on(system.claim(id, Timestamp::from_millis(2))),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(
        !store
            .contains(
                &crate::keys::lease_key(
                    system.namespace(),
                    &QueueName::try_new("default").expect("queue is valid"),
                    &id,
                )
                .expect("lease key is valid"),
            )
            .expect("lease lookup succeeds")
    );
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
fn given_terminal_acknowledgement_then_public_signature_consumes_claim_authority() {
    let _ = terminal_acknowledgement_signature::<FakeStore>;
}

fn dead_lettered(system: &JobSystem<FakeStore>, id: u8) -> (JobId, ExecutionId, u64, OperationId) {
    let job_id = JobId::from([id; 16]);
    block_on(system.enqueue_raw(low_volume_job(id, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    let execution = claim.record().execution_id;
    block_on(system.apply_outcome(
        claim,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("permanent").expect("code is valid"),
        },
        Timestamp::from_millis(1),
    ))
    .expect("dead-letter commits");
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &job_id).expect("job key")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let operation_value = block_on(
        system
            .store()
            .get(crate::keys::operation_key(system.namespace(), &job_id).expect("operation key")),
    )
    .expect("operation read succeeds")
    .expect("operation exists");
    let operation = crate::keys::decode_active_operation(&operation_value, &job_id)
        .expect("operation decodes")
        .0;
    (job_id, execution, record.revision, operation)
}

#[test]
fn given_a_terminal_failure_when_dead_lettering_then_the_bounded_dlq_route_is_written() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let (id, _, _, _) = dead_lettered(&system, 1);
    let record = crate::codec::decode_job_record(
        &block_on(
            system
                .store()
                .get(crate::keys::job_key(system.namespace(), &id).expect("job key")),
        )
        .expect("job read succeeds")
        .expect("job exists"),
    )
    .expect("record decodes");
    assert!(matches!(record.state, JobState::DeadLettered));
    assert!(
        block_on(system.store().get(
            crate::keys::dead_letter_key(system.namespace(), &record.queue, &id,).expect("dlq key")
        ))
        .expect("dlq read succeeds")
        .is_some()
    );
    assert!(
        block_on(system.store().get(
            crate::keys::lease_key(system.namespace(), &record.queue, &id,).expect("lease key"),
        ))
        .expect("lease read succeeds")
        .is_none()
    );
    assert!(
        block_on(
            system
                .store()
                .get(crate::keys::payload_key(system.namespace(), &id, 0).expect("payload key"))
        )
        .expect("payload read succeeds")
        .is_some()
    );
}

#[test]
fn given_a_leased_job_with_a_foreign_namespace_when_corrupt_payload_recovery_reloads_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([10; 16]);
    block_on(system.enqueue_raw(low_volume_job(10, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let mut record = claim.record().clone();
    record.namespace = Namespace::try_new(b"foreign").expect("foreign namespace is valid");
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(crate::failure::dead_letter_by_id(
            &system,
            id,
            Timestamp::from_millis(2),
        )),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not quarantine or rewrite the leased job"
    );
}

#[test]
fn given_a_leased_job_with_a_foreign_payload_chunk_when_corrupt_payload_recovery_reloads_then_payload_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([11; 16]);
    block_on(system.enqueue_raw(low_volume_job(11, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let mut record = claim.record().clone();
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
        block_on(crate::failure::dead_letter_by_id(
            &system,
            id,
            Timestamp::from_millis(2),
        )),
        Err(JobSystemError::PayloadCorrupt)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "payload identity rejection must not quarantine or rewrite the leased job"
    );
}

#[test]
fn given_corrupt_payload_under_a_scoped_lease_when_quarantined_then_original_permits_are_released_atomically()
 {
    let store = FakeStore::new();
    let system = system(
        store.clone(),
        FairnessPolicy::from(std::num::NonZeroU16::MIN),
        12,
    );
    let job = crate::test_helper::job(
        12,
        bytes::Bytes::from_static(b"payload"),
        crate::test_helper::scoped_fairness(),
        Timestamp::ZERO,
        None,
        None,
    );
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
    let permits = claim.permit_keys().to_vec();
    assert!(!permits.is_empty());
    store
        .delete_raw(&claim.record().payload.chunk_keys[0])
        .expect("corrupt payload");
    block_on(crate::failure::dead_letter_by_id(
        &system,
        id,
        Timestamp::from_millis(1),
    ))
    .expect("quarantine commits");
    let key = crate::keys::job_key(system.namespace(), &id).expect("job key");
    let record =
        crate::codec::decode_job_record(&block_on(store.get(key)).expect("read").expect("job"))
            .expect("decode");
    assert!(matches!(record.state, JobState::DeadLettered));
    for key in permits {
        assert!(block_on(store.get(key)).expect("permit read").is_none());
    }
    assert!(block_on(system.claim(id, Timestamp::from_millis(2))).is_err());
}

#[test]
fn given_replaced_permit_when_corrupt_payload_is_quarantined_then_new_owners_permit_is_preserved() {
    let store = FakeStore::new();
    let system = system(
        store.clone(),
        FairnessPolicy::from(std::num::NonZeroU16::MIN),
        13,
    );
    let job = crate::test_helper::job(
        13,
        bytes::Bytes::from_static(b"payload"),
        crate::test_helper::scoped_fairness(),
        Timestamp::ZERO,
        None,
        None,
    );
    let id = job.job_id;
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim");
    let key = claim.permit_keys()[0].clone();
    let mut replacement_record = claim.record().clone();
    replacement_record.job_id = JobId::from([14; 16]);
    let replacement = crate::keys::permit_value_for_record(&replacement_record)
        .expect("replacement permit encodes");
    store
        .put_raw(key.clone(), replacement.clone())
        .expect("replace permit");
    block_on(crate::failure::dead_letter_by_id(
        &system,
        id,
        Timestamp::from_millis(1),
    ))
    .expect("quarantine");
    assert_eq!(block_on(store.get(key)).expect("read"), Some(replacement));
}

#[test]
fn given_cancellation_then_renewal_loss_when_acknowledging_then_the_job_is_terminal() {
    for (index, handler_outcome) in [(99, false), (100, true)] {
        let store = FakeStore::local();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([index; 16]);
        block_on(system.enqueue_raw(low_volume_job(index, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
        block_on(system.request_job_cancellation(&claim, Timestamp::ZERO))
            .expect("cancellation commits");
        assert!(matches!(
            block_on(system.renew(&mut claim, Timestamp::ZERO)),
            Err(JobSystemError::LeaseLost)
        ));
        if handler_outcome {
            assert!(matches!(
                block_on(system.apply_outcome(claim, JobOutcome::Cancelled, Timestamp::ZERO)),
                Ok(OutcomeResult::Cancelled)
            ));
        } else {
            assert_eq!(
                block_on(system.cancel_claim(claim, Timestamp::ZERO)).expect("acknowledgement"),
                CancellationResult::Cancelled
            );
        }
        assert_eq!(
            block_on(system.expire_job(id, Timestamp::from_millis(2000)))
                .expect("terminal expiry is harmless"),
            ExpiryResult::Unchanged
        );
        let encoded = block_on(store.get(keys::job_key(system.namespace(), &id).expect("key")))
            .expect("read succeeds")
            .expect("terminal job exists");
        assert!(matches!(
            crate::codec::decode_job_record(&encoded)
                .expect("decode")
                .state,
            JobState::Cancelled
        ));
        assert!(
            !store
                .contains(&keys::cancellation_key(system.namespace(), &id).expect("key"))
                .expect("marker lookup")
        );
    }
}

#[test]
fn given_renewal_loss_without_a_control_request_when_worker_cancels_then_authority_is_rejected() {
    let store = FakeStore::local();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([101; 16]);
    block_on(system.enqueue_raw(low_volume_job(101, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let key = keys::job_key(system.namespace(), &id).expect("job key");
    let before = block_on(store.get(key.clone())).expect("read succeeds");
    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::from_millis(2000))),
        Err(JobSystemError::LeaseLost)
    ));
    assert!(matches!(
        block_on(system.apply_outcome(claim, JobOutcome::Cancelled, Timestamp::ZERO)),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(block_on(store.get(key)).expect("read succeeds"), before);
}

#[test]
fn given_an_expired_cancelled_lease_when_acknowledging_then_the_durable_state_is_preserved() {
    for (index, handler_outcome) in [(102, false), (103, true)] {
        let store = FakeStore::local();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([index; 16]);
        block_on(system.enqueue_raw(low_volume_job(index, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
        block_on(system.request_job_cancellation(&claim, Timestamp::ZERO))
            .expect("cancellation commits");
        let key = keys::job_key(system.namespace(), &id).expect("job key");
        let before = block_on(store.get(key.clone())).expect("read succeeds");
        let now = Timestamp::from_millis(1000);
        if handler_outcome {
            assert!(matches!(
                block_on(system.apply_outcome(claim, JobOutcome::Cancelled, now)),
                Err(JobSystemError::LeaseLost)
            ));
        } else {
            assert!(matches!(
                block_on(system.cancel_claim(claim, now)),
                Err(JobSystemError::LeaseLost)
            ));
        }
        assert_eq!(block_on(store.get(key)).expect("read succeeds"), before);
        assert!(
            store
                .contains(&keys::cancellation_key(system.namespace(), &id).expect("marker key"))
                .expect("marker lookup")
        );
    }
}
