use crate::{
    test_helper::{block_on, low_volume_job, system},
    *,
};

fn retry_code() -> OutcomeCode {
    OutcomeCode::try_new("transient").expect("retry code is valid")
}

#[test]
fn given_a_retry_when_the_job_is_claimed_again_then_execution_is_stable_and_attempts_are_unique() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let first = block_on(system.claim(id, Timestamp::ZERO)).expect("first claim commits");
    let execution = first.record().execution_id;
    let first_generation = first.record().generation;
    let first_attempt = first.attempt_id();
    let first_fence = match &first.record().state {
        JobState::Leased(lease) => lease.fence.get(),
        _ => panic!("first claim must be leased"),
    };
    let result = block_on(system.apply_outcome(
        first,
        JobOutcome::Retry {
            class: RetryClass::Transient,
            not_before: None,
            code: retry_code(),
        },
        Timestamp::ZERO,
    ))
    .expect("retry commits");
    let not_before = match result {
        OutcomeResult::Retried { not_before, .. } => not_before,
        other => panic!("expected retry, got {other:?}"),
    };
    let operation =
        block_on(system.store().get(
            crate::keys::operation_key(system.namespace(), &id).expect("operation key is valid"),
        ))
        .expect("operation read succeeds")
        .expect("retry operation marker remains");
    assert_eq!(
        crate::keys::decode_active_operation(&operation, &id)
            .expect("retry operation marker decodes")
            .1,
        first_fence
    );
    let second = block_on(system.claim(id, not_before)).expect("second claim commits");
    assert_eq!(second.record().execution_id, execution);
    assert_eq!(second.record().generation, first_generation + 1);
    assert_ne!(second.attempt_id(), first_attempt);
    assert_eq!(
        match &second.record().state {
            JobState::Leased(lease) => lease.fence.get(),
            _ => panic!("second claim must be leased"),
        },
        first_fence + 1
    );
    assert_eq!(
        second
            .record()
            .attempts
            .as_ref()
            .expect("attempts")
            .attempts
            .get(),
        2
    );
}

#[test]
fn given_a_continuation_with_a_checkpoint_when_applying_it_then_schedule_and_checkpoint_commit_together()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([4; 16]);
    block_on(system.enqueue_raw(low_volume_job(4, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(10),
            checkpoint: bytes::Bytes::from_static(b"checkpoint"),
        },
        Timestamp::ZERO,
    ))
    .expect("continuation commits");
    assert_eq!(
        result,
        OutcomeResult::Continued {
            not_before: Timestamp::from_millis(10)
        }
    );

    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert_eq!(record.state, JobState::Scheduled);
    assert_eq!(record.scheduled_at, Timestamp::from_millis(10));
    assert_eq!(
        record.checkpoint,
        Some(bytes::Bytes::from_static(b"checkpoint"))
    );
    assert!(
        block_on(
            system.store().get(
                crate::keys::due_key(system.namespace(), &record.queue, record.scheduled_at, &id,)
                    .expect("due key"),
            )
        )
        .expect("due read succeeds")
        .is_some()
    );
}

#[test]
fn given_a_continuation_past_the_age_bound_when_applying_it_then_the_job_is_dead_lettered() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([5; 16]);
    block_on(system.enqueue_raw(
        crate::test_helper::job(
            5,
            bytes::Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            Some(Timestamp::from_millis(1)),
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(1),
            checkpoint: bytes::Bytes::new(),
        },
        Timestamp::from_millis(1),
    ))
    .expect("age exhaustion commits");
    assert!(matches!(
        result,
        OutcomeResult::DeadLettered { ref code } if code.as_str() == "age_exhausted"
    ));
}

#[test]
fn given_successful_continuations_when_retry_limits_are_reached_then_each_segment_gets_a_fresh_retry_budget()
 {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([6; 16]);
    let mut job = low_volume_job(6, Timestamp::ZERO);
    job.retry_override = Some(RetrySelection::Custom(
        RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: std::num::NonZeroU16::new(1).expect("attempt bound is non-zero"),
            maximum_age: std::time::Duration::from_millis(1),
            minimum_backoff: std::time::Duration::from_millis(1),
            maximum_backoff: std::time::Duration::from_millis(1),
            multiplier: BackoffMultiplier::try_from(2_u32).expect("multiplier is non-zero"),
        })
        .expect("retry policy is valid"),
    ));
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(1),
            checkpoint: bytes::Bytes::from_static(b"page-1"),
        },
        Timestamp::ZERO,
    ))
    .expect("first continuation commits");
    assert_eq!(
        result,
        OutcomeResult::Continued {
            not_before: Timestamp::from_millis(1)
        }
    );

    let resumed = block_on(system.claim(id, Timestamp::from_millis(1)))
        .expect("continued job remains claimable past the original retry limits");
    assert_eq!(
        resumed.context().expect("resumed context").checkpoint(),
        Some(b"page-1".as_slice())
    );
    assert_eq!(
        resumed
            .record()
            .attempts
            .as_ref()
            .expect("new attempt history")
            .attempts
            .get(),
        1
    );

    let result = block_on(system.apply_outcome(
        resumed,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(2),
            checkpoint: bytes::Bytes::from_static(b"page-2"),
        },
        Timestamp::from_millis(1),
    ))
    .expect("second continuation commits");
    assert_eq!(
        result,
        OutcomeResult::Continued {
            not_before: Timestamp::from_millis(2)
        }
    );
    block_on(system.claim(id, Timestamp::from_millis(2)))
        .expect("each successful segment renews the retry age window");
}

#[test]
fn given_a_retry_past_the_age_bound_when_applying_it_then_the_job_is_dead_lettered() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    block_on(system.enqueue_raw(
        crate::test_helper::job(
            2,
            bytes::Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            Some(Timestamp::from_millis(1)),
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Retry {
            class: RetryClass::Transient,
            // Full jitter may be zero; the hint makes crossing expiry
            // deterministic.
            not_before: Some(Timestamp::from_millis(1)),
            code: retry_code(),
        },
        Timestamp::ZERO,
    ))
    .expect("age exhaustion commits");
    assert!(matches!(
        result,
        OutcomeResult::DeadLettered { ref code } if code.as_str() == "age_exhausted"
    ));
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
        JobState::DeadLettered
    ));
}

#[test]
fn given_maximum_attempts_when_retries_exhaust_the_budget_then_the_next_retry_is_dead_lettered() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([3; 16]);
    block_on(system.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut now = Timestamp::ZERO;
    for _ in 0..2 {
        let claim = block_on(system.claim(id, now)).expect("claim commits");
        let result = block_on(system.apply_outcome(
            claim,
            JobOutcome::Retry {
                class: RetryClass::Transient,
                not_before: None,
                code: retry_code(),
            },
            now,
        ))
        .expect("retry commits");
        now = match result {
            OutcomeResult::Retried { not_before, .. } => not_before,
            other => panic!("expected retry, got {other:?}"),
        };
    }
    let claim = block_on(system.claim(id, now)).expect("third claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Retry {
            class: RetryClass::Transient,
            not_before: None,
            code: retry_code(),
        },
        now,
    ))
    .expect("attempt exhaustion commits");
    assert!(matches!(
        result,
        OutcomeResult::DeadLettered { ref code } if code.as_str() == "attempts_exhausted"
    ));
}

#[test]
fn given_elapsed_handler_work_when_continuing_immediately_then_checkpoint_remains_due() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([40; 16]);
    block_on(system.enqueue_raw(low_volume_job(40, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::ZERO,
            checkpoint: bytes::Bytes::from_static(b"next-page"),
        },
        Timestamp::from_millis(10),
    ))
    .expect("handler elapsed time does not invalidate an immediate continuation");
    assert_eq!(
        result,
        OutcomeResult::Continued {
            not_before: Timestamp::ZERO
        }
    );
    let resumed =
        block_on(system.claim(id, Timestamp::from_millis(10))).expect("continuation is due");
    assert_eq!(
        resumed.context().expect("context").checkpoint(),
        Some(b"next-page".as_slice())
    );
}

#[test]
fn given_a_continuation_before_claim_time_when_applying_it_then_state_is_unchanged() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([41; 16]);
    block_on(system.enqueue_raw(low_volume_job(41, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::from_millis(10))).expect("claim commits");
    let before = store.snapshot();
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(9),
            checkpoint: bytes::Bytes::from_static(b"next-page"),
        },
        Timestamp::from_millis(20),
    ));
    assert!(matches!(
        result,
        Err(JobSystemError::Validation(ValidationError::Ordering {
            field: "continuation schedule"
        }))
    ));
    assert_eq!(store.snapshot(), before);
}

#[test]
fn given_expiry_during_handler_work_when_continuing_immediately_then_job_is_dead_lettered() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([42; 16]);
    let mut job = low_volume_job(42, Timestamp::ZERO);
    job.expires_at = Some(Timestamp::from_millis(5));
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    let result = block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::ZERO,
            checkpoint: bytes::Bytes::from_static(b"next-page"),
        },
        Timestamp::from_millis(10),
    ))
    .unwrap();
    assert!(
        matches!(result, OutcomeResult::DeadLettered { code } if code.as_str() == "age_exhausted")
    );
}

#[test]
fn given_elapsed_handler_work_when_continuing_then_new_retry_age_starts_at_completion() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([43; 16]);
    let mut job = low_volume_job(43, Timestamp::ZERO);
    job.retry_override = Some(RetrySelection::Custom(
        RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: std::num::NonZeroU16::MIN,
            maximum_age: std::time::Duration::from_millis(1),
            minimum_backoff: std::time::Duration::from_millis(1),
            maximum_backoff: std::time::Duration::from_millis(1),
            multiplier: BackoffMultiplier::try_from(2_u32).unwrap(),
        })
        .unwrap(),
    ));
    block_on(system.enqueue_raw(job, Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    block_on(system.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::ZERO,
            checkpoint: bytes::Bytes::from_static(b"next-page"),
        },
        Timestamp::from_millis(10),
    ))
    .unwrap();
    let resumed = block_on(system.claim(id, Timestamp::from_millis(10)))
        .expect("successful continuation receives a fresh retry age");
    assert_eq!(
        resumed.context().unwrap().checkpoint(),
        Some(b"next-page".as_slice())
    );
}
