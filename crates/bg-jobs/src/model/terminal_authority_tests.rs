use crate::{
    FairnessPolicy, FakeStore, JobId, JobOutcome, JobState, JobStore, OutcomeCode, Timestamp,
    failure::{RedriveExecution, RedriveRequest},
    test_helper::{block_on, low_volume_job, system},
};

#[test]
fn given_a_terminal_job_when_redriven_then_its_projection_witness_is_rejected() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([9; 16]);
    block_on(system.enqueue_raw(low_volume_job(9, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    assert!(block_on(system.terminal_authority(id)).unwrap().is_none());
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    assert!(block_on(system.terminal_authority(id)).unwrap().is_none());
    let live = claim.context().unwrap().effect_authority().unwrap();
    block_on(system.apply_outcome(
        claim,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("permanent").unwrap(),
        },
        Timestamp::from_millis(1),
    ))
    .unwrap();
    let authority = block_on(system.terminal_authority(id)).unwrap().unwrap();
    assert_eq!(authority.state(), &JobState::DeadLettered);
    assert_eq!(authority.outcome().unwrap().as_str(), "permanent");
    assert_eq!(format!("{authority:?}"), "JobTerminalAuthority(<redacted>)");
    let values = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(authority.matches_observations(&values).unwrap());
    assert!(
        !live
            .matches_observations(&values, Timestamp::from_millis(1))
            .unwrap()
    );
    let crate::LifecycleObservation::Current {
        record,
        operation_id: Some(operation),
        ..
    } = block_on(system.observe_lifecycle(id)).unwrap()
    else {
        panic!("terminal record")
    };
    block_on(system.redrive_job(
        id,
        RedriveRequest::new(
            record.revision,
            operation,
            RedriveExecution::ReuseExecutionId,
            Timestamp::from_millis(2),
        ),
    ))
    .unwrap();
    let values = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(!authority.matches_observations(&values).unwrap());
    assert!(block_on(system.terminal_authority(id)).unwrap().is_none());
    assert!(authority.matches_observations(&[]).is_err());
}

#[test]
fn given_missing_suspended_and_cancelled_jobs_when_issuing_terminal_authority_then_only_cancelled_is_allowed()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([8; 16]);
    assert!(block_on(system.terminal_authority(id)).unwrap().is_none());
    block_on(system.enqueue_raw(low_volume_job(8, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    block_on(system.suspend_job(id)).unwrap();
    assert!(block_on(system.terminal_authority(id)).unwrap().is_none());
    block_on(system.resume_job(id)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    block_on(system.request_job_cancellation(&claim, Timestamp::ZERO)).unwrap();
    block_on(system.cancel_claim(claim, Timestamp::ZERO)).unwrap();
    let authority = block_on(system.terminal_authority(id)).unwrap().unwrap();
    assert_eq!(authority.state(), &JobState::Cancelled);
    let values = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(authority.matches_observations(&values).unwrap());
    assert!(!authority.matches_observations(&[None, None]).unwrap());
}

#[test]
fn given_a_retried_job_when_cancelled_then_its_terminal_projection_has_no_retry_error() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([7; 16]);
    block_on(system.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    block_on(system.apply_outcome(
        claim,
        JobOutcome::Retry {
            class: crate::RetryClass::Transient,
            not_before: None,
            code: OutcomeCode::try_new("previous_retry").unwrap(),
        },
        Timestamp::from_millis(1),
    ))
    .unwrap();
    block_on(system.cancel_job(id, Timestamp::from_millis(2))).unwrap();
    let authority = block_on(system.terminal_authority(id)).unwrap().unwrap();
    assert_eq!(authority.state(), &JobState::Cancelled);
    assert!(authority.outcome().is_none());
}
